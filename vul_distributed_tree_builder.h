/** @file distributed_tree_builder.h
 *
 *  The generic template for building a distributed tree.
 *
 *  @author Dongryeol Lee (dongryel@cc.gatech.edu)
 */

#ifndef CORE_PARALLEL_DISTRIBUTED_TREE_BUILDER_H
#define CORE_PARALLEL_DISTRIBUTED_TREE_BUILDER_H

#include <algorithm>
#include <numeric>
#include <boost/mpi.hpp>
#include "core/metric_kernels/abstract_metric.h"
#include "core/parallel/parallel_sample_sort.h"
#include "core/table/offset_dense_matrix.h"
#include "core/table/memory_mapped_file.h"

namespace core {
namespace table {
extern core::table::MemoryMappedFile *global_m_file_;
};
};

namespace core {
namespace parallel {
template<typename DistributedTableType>
class DistributedTreeBuilder {
  public:
    typedef typename DistributedTableType::TableType TableType;

    typedef typename DistributedTableType::TreeType TreeType;

    typedef typename TableType::OldFromNewIndexType OldFromNewIndexType;

    typedef core::table::SampleDenseMatrix<OldFromNewIndexType>
    SampleDenseMatrixType;

  private:
    DistributedTableType *distributed_table_;

    double sampling_rate_;

  private:

    static bool MortonOrderNodes_(TreeType *first_node, TreeType *second_node) {
      return
        core::math::MortonOrderPoints(
          first_node->bound().center(), second_node->bound().center());
    }

    void AugmentNodes_(
      boost::mpi::communicator &world,
      const typename TreeType::BoundType &root_bound,
      std::vector<TreeType *> &top_leaf_nodes) {

      core::table::DensePoint tmp_point;
      arma::vec tmp_point_alias;
      tmp_point.Init(top_leaf_nodes[0]->bound().center().length());
      core::table::DensePointToArmaVec(tmp_point, &tmp_point_alias);
      int num_additional = world.size() - top_leaf_nodes.size();
      int num_samples = std::max(1, core::math::RandInt(top_leaf_nodes.size()));

      // Randomly add new dummy nodes with randomly chosen centroids
      // averaged.
      for(int j = 0; j < num_additional; j++) {
        root_bound.RandomPointInside(&tmp_point_alias);
        for(int i = 0; i < num_samples; i++) {
          arma::vec random_node_center;
          core::table::DensePointToArmaVec(
            top_leaf_nodes[
              core::math::RandInt(top_leaf_nodes.size())]->bound().center(),
            &random_node_center);
          tmp_point_alias += random_node_center;
        }
        tmp_point_alias = (1.0 / static_cast<double>(num_samples)) *
                          tmp_point_alias;
        top_leaf_nodes.push_back(new TreeType());
        top_leaf_nodes[ top_leaf_nodes.size() - 1 ]->bound().center().Copy(
          tmp_point);
      }
    }

    void SetupGatherPointers_(
      TableType &sampled_table, const std::vector<int> &counts,
      std::vector< SampleDenseMatrixType > *gather_pointers_out) {

      // Have the pointers point to the right position based on the
      // prefix sum position.
      gather_pointers_out->resize(counts.size());
      int starting_column_index = 0;
      for(unsigned int i = 0; i < counts.size(); i++) {
        (*gather_pointers_out)[i].Init(
          sampled_table.data(), sampled_table.old_from_new(),
          starting_column_index, counts[i]);
        starting_column_index += counts[i];
      }
    }

    void GetLeafNodeMembershipCounts_(
      const core::metric_kernels::AbstractMetric &metric_in,
      const std::vector<TreeType *> &top_leaf_nodes,
      std::vector< std::vector<int> > *assigned_point_indices,
      std::vector<int> *membership_counts_per_node) {

      assigned_point_indices->resize(0);
      assigned_point_indices->resize(top_leaf_nodes.size());
      membership_counts_per_node->resize(top_leaf_nodes.size());
      std::fill(
        membership_counts_per_node->begin(),
        membership_counts_per_node->end(), 0.0);

      // Loop through each point and find the closest leaf node.
      for(int i = 0; i < distributed_table_->local_table()->n_entries(); i++) {
        core::table::DensePoint point;
        distributed_table_->local_table()->get(i, &point);

        // Loop through each leaf node.
        double min_squared_mid_distance = std::numeric_limits<double>::max();
        int min_index = -1;
        for(unsigned int j = 0; j < top_leaf_nodes.size(); j++) {
          const typename TreeType::BoundType &leaf_node_bound =
            top_leaf_nodes[j]->bound();

          // Compute the squared mid-distance.
          double squared_mid_distance = leaf_node_bound.MidDistanceSq(
                                          metric_in, point);
          if(squared_mid_distance < min_squared_mid_distance) {
            min_squared_mid_distance = squared_mid_distance;
            min_index = j;
          }
        }

        // Output the assignments.
        (*assigned_point_indices)[min_index].push_back(i);
        (*membership_counts_per_node)[min_index]++;
      }
    }

    void ReshufflePoints_(
      const core::metric_kernels::AbstractMetric &metric_in,
      boost::mpi::communicator &world,
      const std::vector<TreeType *> &top_leaf_nodes) {

      // Determine the membership counts.
      std::vector< std::vector<int> > assigned_point_indices;
      std::vector<int> membership_counts_per_node;
      GetLeafNodeMembershipCounts_(
        metric_in, top_leaf_nodes,
        &assigned_point_indices, &membership_counts_per_node);

      // Do an all-to-all to figure out the new table sizes for each
      // process.
      std::vector<int> reshuffled_contributions;
      boost::mpi::all_to_all(
        world, membership_counts_per_node, reshuffled_contributions);
      int total_num_points_owned =
        std::accumulate(
          reshuffled_contributions.begin(), reshuffled_contributions.end(), 0);

      // Allocate a new table to get all the points.
      TableType *new_local_table =
        (core::table::global_m_file_) ?
        core::table::global_m_file_->Construct<TableType>() : new TableType();
      new_local_table->Init(
        distributed_table_->n_attributes(), total_num_points_owned,
        world.rank());

      // Setup points so that they will be reshuffled.
      std::vector<SampleDenseMatrixType> points_to_be_distributed;
      points_to_be_distributed.resize(world.size());
      for(unsigned int i = 0; i < points_to_be_distributed.size(); i++) {
        points_to_be_distributed[i].Init(
          distributed_table_->local_table()->data(),
          distributed_table_->local_table()->old_from_new(),
          assigned_point_indices[i]);
      }
      std::vector<SampleDenseMatrixType> reshuffled_points;
      SetupGatherPointers_(
        *new_local_table, reshuffled_contributions, &reshuffled_points);
      boost::mpi::all_to_all(
        world, points_to_be_distributed, reshuffled_points);

      // Set it to the newly shuffled table.
      distributed_table_->set_local_table(new_local_table);
    }

    void BuildSampleTree_(
      const core::metric_kernels::AbstractMetric &metric_in,
      boost::mpi::communicator &world,
      std::vector<TreeType *> *top_leaf_nodes_out) {

      // Each process generates a random subset of the data points to
      // send to the master. This is a MPI gather operation.
      TableType sampled_table;
      std::vector<int> sampled_indices;
      SelectSubset_(&sampled_indices);

      // Send the number of points chosen in this process to the
      // master so that the master can allocate the appropriate amount
      // of space to receive all the points.
      std::vector<int> counts;
      int local_sampled_indices_size = static_cast<int>(
                                         sampled_indices.size());
      boost::mpi::gather(world, local_sampled_indices_size, counts, 0);

      // The master process allocates the sample table and gathers the
      // chosen samples from each process.
      SampleDenseMatrixType local_pointer;
      local_pointer.Init(
        distributed_table_->local_table()->data(),
        distributed_table_->local_table()->old_from_new(),
        sampled_indices);
      std::vector<SampleDenseMatrixType> gather_pointers;
      if(world.rank() == 0) {
        int total_num_samples = std::accumulate(
                                  counts.begin(), counts.end(), 0);
        sampled_table.Init(
          distributed_table_->n_attributes(), total_num_samples);
        SetupGatherPointers_(sampled_table, counts, &gather_pointers);
      }
      boost::mpi::gather(world, local_pointer, gather_pointers, 0);

      // Index the tree up so that the number of leaf nodes matches
      // the number of processes. If missing some nodes, then sample a
      // region and try to make up a node.
      if(world.rank() == 0) {
        sampled_table.IndexData(metric_in, 1, world.size());
        sampled_table.get_leaf_nodes(
          sampled_table.get_tree(), top_leaf_nodes_out);
        if(top_leaf_nodes_out->size() <
            static_cast<unsigned int>(world.size())) {
          AugmentNodes_(
            world, sampled_table.get_tree()->bound(), *top_leaf_nodes_out);
        }

        // Sort the nodes by Z-ordering their centroids.
        std::sort(
          top_leaf_nodes_out->begin(), top_leaf_nodes_out->end(),
          MortonOrderNodes_);
      }
      boost::mpi::broadcast(world, *top_leaf_nodes_out, 0);
    }

    void SelectSubset_(
      std::vector<int> *sampled_indices_out) {

      std::vector<int> indices(
        distributed_table_->local_table()->n_entries(), 0);
      for(unsigned int i = 0; i < indices.size(); i++) {
        indices[i] = i;
      }
      int num_elements =
        std::max(
          (int)
          floor(
            sampling_rate_ *
            distributed_table_->local_table()->n_entries()), 1);
      std::random_shuffle(indices.begin(), indices.end());

      for(int i = 0; i < num_elements; i++) {
        sampled_indices_out->push_back(indices[i]);
      }
    }

  public:
    void Init(
      DistributedTableType &distributed_table_in, double sampling_rate_in) {
      distributed_table_ = &distributed_table_in;
      sampling_rate_ = sampling_rate_in;
    }

    void Build(
      const core::metric_kernels::AbstractMetric &metric_in,
      boost::mpi::communicator &world) {

      // Build the initial sample tree.
      std::vector<TreeType *> top_leaf_nodes;
      BuildSampleTree_(metric_in, world, &top_leaf_nodes);

      // For each process, determine the membership of each points to
      // each of the top leaf nodes and do an all-to-all to do the
      // reshuffle.
      ReshufflePoints_(metric_in, world, top_leaf_nodes);

      // Recompute the centroids of each machine.


      // Compute two prefix sums to do a re-distribution. This works
      // assuming that the centroids are roughly in Morton order.

      // Recompute the centroids and repeat.

    }
};
};
};

#endif

