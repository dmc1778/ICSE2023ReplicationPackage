#ifndef HMM_H
#define HMM_H


#include "fastlib/fastlib.h"
#include "diag_gaussian.h"
#include "multinomial.h"
#include "mixture.h"
#include "la_utils.h"

#define MULTINOMIAL 1
#define GAUSSIAN 2
#define MIXTURE 3


template <typename TDistribution>
class HMM {

 private:

  int n_states_;
  int n_dims_;
  int type_;
  double min_variance_;
  int n_components_;

 public:

  // p_initial, p_transition, and state_distributions are public because
  // it's ever so much easier

  Vector p_initial;

  /* rows sum to 1: p_transition.get(i,j) is P(s_j | s_i) */
  Matrix p_transition; //

  TDistribution* state_distributions;
  
    

 public:


  void Init(int n_states_in, int n_dims_in, int type_in) {
    Init(n_states_in, n_dims_in, type_in, 0);
  }

  void Init(int n_states_in, int n_dims_in, int type_in,
	    double min_variance_in) {
    Init(n_states_in, n_dims_in, type_in, min_variance_in, 1);
  }

  void Init(int n_states_in, int n_dims_in,
	    int type_in, double min_variance_in,
	    int n_components_in) {
    n_states_ = n_states_in;
    n_dims_ = n_dims_in;
    type_ = type_in;
    min_variance_ = min_variance_in;
    n_components_ = n_components_in;
    
    p_initial.Init(n_states_);
    p_transition.Init(n_states_, n_states_);
    
    state_distributions = 
      (TDistribution*) malloc(n_states_ * sizeof(TDistribution));
    for(int i = 0; i < n_states_; i++) {
      state_distributions[i].Init(n_dims_, min_variance_in, n_components_);
    }
  }

    
  void RandomlyInitialize() {
    double uniform = ((double) 1) / ((double) n_states_);
    
    for(int i = 0; i < n_states_; i++) {
      p_initial[i] = uniform;
      for(int j = 0; j < n_states_; j++) {
	p_transition.set(j, i, uniform);
      }
      
      state_distributions[i].RandomlyInitialize();
    }
  }
 
  void ScaleForwardVar(double* c, Vector *p_forward_var) {
    (*c) = ((double)1) / Sum(*p_forward_var);
    la::Scale(*c, p_forward_var);
  }
  
  // no risk
  void ComputePqqt(const Matrix &forward_vars,
		   const Matrix &backward_vars,
		   const Matrix &p_x_given_q,
		   ArrayList<Matrix>* p_p_qq_t) {
    ArrayList<Matrix> &p_qq_t = *p_p_qq_t;
    
    int sequence_length = forward_vars.n_cols();
    
    p_qq_t.Init(n_states_);
    for(int i = 0; i < n_states_; i++) {
      p_qq_t[i].Init(n_states_, sequence_length);
      
      for(int t = 0; t < sequence_length - 1; t++) {
	for(int j = 0; j < n_states_; j++) {
	  //consider transposing forward_vars and p_transition for efficiency
	  p_qq_t[i].set(j, t,
			forward_vars.get(i, t)
			* p_transition.get(i, j)
			* p_x_given_q.get(j, t + 1)
			* backward_vars.get(j, t + 1));
	}
      }
    }
  }

  // no risk
  void ComputePqt(const Matrix &forward_vars,
		  const Matrix &backward_vars,
		  const Vector &scaling_vars,
		  const ArrayList<Matrix> &p_qq_t,
		  Matrix* p_p_qt) {
    Matrix &p_qt = *p_p_qt;

    int sequence_length = forward_vars.n_cols();

    p_qt.Init(sequence_length, n_states_);

    for(int i = 0; i < n_states_; i++) {
      for(int t = 0; t < sequence_length; t++) {
	p_qt.set(t, i, 
		 forward_vars.get(i, t)
		 * backward_vars.get(i, t)
		 / scaling_vars.get(t));
      }
    }
  }


  template<typename T>
  void ExpectationStep(const GenMatrix<T> &sequence,
		       Matrix* p_p_x_given_q,
		       ArrayList<Matrix>* p_p_x_given_mixture_q,
		       ArrayList<Matrix>* p_p_qq_t,
		       Matrix* p_p_qt,
		       double* p_neg_likelihood) {
    // embrace readability!
    Matrix &p_x_given_q = *p_p_x_given_q;
    ArrayList<Matrix> &p_x_given_mixture_q = *p_p_x_given_mixture_q;
    ArrayList<Matrix> &p_qq_t = *p_p_qq_t;
    Matrix &p_qt = *p_p_qt;
    double &neg_likelihood = *p_neg_likelihood;


    if(type_ == MIXTURE) {
      ComputePxGivenMixtureQ(sequence, &p_x_given_q,
			     &p_x_given_mixture_q);
    }
    else {
      ComputePxGivenQ(sequence, &p_x_given_q);
      p_x_given_mixture_q.Init(0);
    }
    
    Matrix forward_vars;
    Matrix backward_vars;
    Vector scaling_vars;
    ForwardAlgorithm(p_x_given_q, &scaling_vars, &forward_vars);
    BackwardAlgorithm(p_x_given_q, scaling_vars, &backward_vars);
    
    ComputePqqt(forward_vars, backward_vars, p_x_given_q, &p_qq_t);
    ComputePqt(forward_vars ,backward_vars, scaling_vars, p_qq_t, &p_qt);

    neg_likelihood = 0;
    int sequence_length = sequence.n_cols();
    for(int i = 0; i < sequence_length; i++) {
      neg_likelihood += log(scaling_vars[i]);
    }
  }

  // no risk
  template<typename T>
  void ComputePxGivenQ(const GenMatrix<T> &sequence,
		       Matrix* p_p_x_given_q) {
    Matrix &p_x_given_q = *p_p_x_given_q;
    
    int sequence_length = sequence.n_cols();
    p_x_given_q.Init(n_states_, sequence_length);
    
    for(int t = 0; t < sequence_length; t++) {
      GenVector<T> x_t;
      sequence.MakeColumnVector(t, &x_t);
      for(int i = 0; i < n_states_; i++) {
	p_x_given_q.set(i, t, state_distributions[i].Pdf(x_t));
      }
    }
  }

  // should be no risk after addressing division
  // using "if(p_x_given_q.get(i, t) != 0)..."
  template<typename T>
  void ComputePxGivenMixtureQ(const GenMatrix<T> &sequence,
			      Matrix* p_p_x_given_q,
			      ArrayList<Matrix>* p_p_x_given_mixture_q) {
    Matrix &p_x_given_q = *p_p_x_given_q;
    ArrayList<Matrix> &p_x_given_mixture_q = *p_p_x_given_mixture_q;
    
    int sequence_length = sequence.n_cols();
    p_x_given_q.Init(n_states_, sequence_length);
    p_x_given_q.SetZero();

    p_x_given_mixture_q.Init(n_components_);
    for(int k = 0; k < n_components_; k++) {
      p_x_given_mixture_q[k].Init(n_states_, sequence_length);
    }

    for(int k = 0; k < n_components_; k++) {
      for(int t = 0; t < sequence_length; t++) {
	GenVector<T> xt;
	sequence.MakeColumnVector(t, &xt);

	for(int i = 0; i < n_states_; i++) {
	  double p_xt_given_qik = state_distributions[i].PkthComponent(xt, k);
	  p_x_given_mixture_q[k].set(i, t,
				     p_xt_given_qik);
	  p_x_given_q.set(i, t,
			  p_x_given_q.get(i, t) + p_xt_given_qik);
	}
      }
    }

    for(int k = 0; k < n_components_; k++) {
      for(int t = 0; t < sequence_length; t++) {
	for(int i = 0; i < n_states_; i++) {
	  if(p_x_given_q.get(i, t) != 0) {
	    p_x_given_mixture_q[k].set(i, t,
				       p_x_given_mixture_q[k].get(i, t)
				       / p_x_given_q.get(i, t));
	  }
	}
      }
    }
  }

  // no risk
  void ForwardAlgorithm(const Matrix &p_x_given_q,
			Vector* p_scaling_vars, 
			Matrix* p_forward_vars) {
    Vector& scaling_vars = *p_scaling_vars;
    Matrix& forward_vars = *p_forward_vars;

    int sequence_length = p_x_given_q.n_cols();

    scaling_vars.Init(sequence_length);
    forward_vars.Init(n_states_, sequence_length);

    Vector forward_0;
    forward_vars.MakeColumnVector(0, &forward_0);

    Vector p_x0_given_q;
    p_x_given_q.MakeColumnVector(0, &p_x0_given_q);

    HadamardMultiplyOverwrite(p_initial, p_x0_given_q, &forward_0);
    ScaleForwardVar(&(scaling_vars[0]), &forward_0);
    printf("scaling_vars[0] = %f\n", scaling_vars[0]);

    for(int t = 0; t < sequence_length - 1; t++) {
      Vector forward_t;
      forward_vars.MakeColumnVector(t, &forward_t);

      Vector forward_t_plus_1;
      forward_vars.MakeColumnVector(t + 1, &forward_t_plus_1);

      Vector p_xt_plus_1_given_q;
      p_x_given_q.MakeColumnVector(t + 1, &p_xt_plus_1_given_q);

      la::MulOverwrite(forward_t, p_transition, &forward_t_plus_1);
      HadamardMultiplyBy(p_xt_plus_1_given_q, &forward_t_plus_1);
      ScaleForwardVar(&(scaling_vars[t + 1]), &forward_t_plus_1);
    }
  }

  // no risk
  void BackwardAlgorithm(const Matrix &p_x_given_q,
			 const Vector &scaling_vars,
			 Matrix *p_backward_vars) {
    Matrix& backward_vars = *p_backward_vars;
    
    int sequence_length = p_x_given_q.n_cols();
    
    backward_vars.Init(n_states_, sequence_length);
    
    Vector backward_T_minus_1;
    backward_vars.MakeColumnVector(sequence_length - 1, &backward_T_minus_1);
    
    backward_T_minus_1.SetAll(scaling_vars[sequence_length - 1]);

    for(int t = sequence_length - 2; t >= 0; t--) {
      Vector backward_t_plus_1;
      backward_vars.MakeColumnVector(t + 1, &backward_t_plus_1);

      Vector backward_t;
      backward_vars.MakeColumnVector(t, &backward_t);

      Vector p_xt_plus_1_given_q;
      p_x_given_q.MakeColumnVector(t + 1, &p_xt_plus_1_given_q);

      Vector result;
      HadamardMultiplyInit(p_xt_plus_1_given_q, backward_t_plus_1,
			   &result);
      la::MulOverwrite(p_transition, result, &backward_t);
      la::Scale(scaling_vars[t], &backward_t);
    }
  }


  void SwapHMMParameters(HMM* p_other_hmm) {
    HMM &other_hmm = *p_other_hmm;

    // SWAP other and this HMMs' initial state probabilities
    //                           state transition probabilities
    //                           state distributions
    TDistribution* temp_state_distributions;
    temp_state_distributions = state_distributions;
    state_distributions = other_hmm.state_distributions;
    other_hmm.state_distributions = temp_state_distributions;
    
    Vector temp_p_initial;
    temp_p_initial.Own(&p_initial);
    p_initial.Destruct();
    p_initial.Own(&(other_hmm.p_initial));
    other_hmm.p_initial.Destruct();
    other_hmm.p_initial.Own(&temp_p_initial);
    
    Matrix temp_p_transition;
    temp_p_transition.Own(&p_transition);
    p_transition.Destruct();
    p_transition.Own(&(other_hmm.p_transition));
    other_hmm.p_transition.Destruct();
    other_hmm.p_transition.Own(&temp_p_transition);
  }


  template<typename T>
  void InitParameters(const ArrayList<GenMatrix<T> > &sequences) {
    double uniform = ((double) 1) / ((double) n_states_);
    
    for(int i = 0; i < n_states_; i++) {
      p_initial[i] = uniform;
      for(int j = 0; j < n_states_; j++) {
	p_transition.set(j, i, uniform);
      }
    }

    if(type_ == MULTINOMIAL) {
      for(int i = 0; i < n_states_; i++) {
	state_distributions[i].RandomlyInitialize();
      }
    }
    else if(type_ == GAUSSIAN) {

      for(int i = 0; i < n_states_; i++) {
	state_distributions[i].SetZero();
      }

      // k-means cluster the data into n_states clusters

      Vector cluster_memberships;
      int cluster_counts[n_states_];
      KMeans(sequences, n_states_, 100, &cluster_memberships);

      int n_sequences = sequences.length();
      int i = 0;
      for(int m = 0; m < n_sequences; m++) {
	Matrix &sequence = sequences[i];
	int sequence_length = sequence.n_cols();
	for(int j = 0; j < sequence_length; j++) {
	  Vector point;
	  sequence.MakeColumnVector(j, &point);
	  state_distributions[cluster_memberships[i]].Accumulate(point, 1,
								 0);
	  i++;
	}
      }
      for(int i = 0; i < n_states_; i++) {
	state_distributions[i].Normalize(cluster_counts);
      }
    }
    else if(type_ == MIXTURE) {
      // crazy!

    }

  }


  template<typename T>
  void KMeans(const ArrayList<GenMatrix<T> > &datasets,
	      int n_clusters,
	      int max_iterations,
	      Vector* p_cluster_memberships,
	      int cluster_counts[]) {
    Vector &cluster_memberships= *p_cluster_memberships;
    
    ArrayList<Vector> cluster_centers;
    cluster_centers.Init(n_clusters);
    for(int k = 0; k < n_clusters; k++) {
      cluster_centers[k].Init(n_dims_);
    }
    
    int n_datasets = datasets.length();
    int n_points = 0;
    for(int m = 0; m < n_datasets; m++) {
      n_points += datasets[m].n_cols();
    }

    int i;

    // random initialization
    cluster_memberships.Init(n_points);
    for(i = 0; i < n_points; i++) {
      cluster_memberships[i] = rand() % n_clusters;
    }

    int iteration_num = 1;
    bool converged = false;
    while(!converged) {
      // update cluster centers using cluster memberships
      for(int k = 0; k < n_clusters; k++) {
	cluster_centers[k].SetZero();
      }
      i = 0;
      for(int m = 0; m < n_datasets; m++) {
	Matrix &data = datasets[i];
	int n_points_in_data = data.n_cols();
	for(int j = 0; j < n_points_in_data; j++) {
	  Vector point;
	  data.MakeColumnVector(j, &point);
	  int cluster_index = cluster_memberships[i];
	  la::AddTo(point, &(cluster_centers[cluster_index]));
	  cluster_counts[cluster_index]++;
	  i++;
	}
      }
      for(int k = 0; k < n_clusters; k++) {
	la::Scale(((double)1) / ((double)(cluster_counts[k])),
		  &(cluster_centers[k]));
      }
    
      // update cluster memberships using cluster centers
      int n_changes = 0;
      i = 0;
      for(int m = 0; m < n_datasets; m++) {
	Matrix &data = datasets[i];
	int n_points_in_data = data.n_cols();
	for(int j = 0; j < n_points_in_data; j++) {
	  Vector point;
	  data.MakeColumnVector(j, &point);
	  double min_dist_sq = std::numeric_limits<double>::max();
	  int nearest_cluster_index = -1;
	  for(int k = 0; k < n_clusters; k++) {
	    double dist_sq =
	      la::DistanceSqEuclidean(point, cluster_centers[k]);
	    if(dist_sq < min_dist_sq) {
	      min_dist_sq = dist_sq;
	      nearest_cluster_index = k;
	    }
	  }
	  if(cluster_memberships[i] != nearest_cluster_index) {
	    n_changes++;
	    cluster_memberships[i] = nearest_cluster_index;
	  }
	  i++;
	}
      }

      iteration_num++;
      if((n_changes == 0) || (iteration_num > max_iterations)) {
	converged = true;
      }
    }
    

  }


 

  template<typename T>
  void BaumWelch(const ArrayList<GenMatrix<T> > &sequences,
		 double neg_likelihood_threshold,
		 int max_iterations) {
    int n_sequences = sequences.size();

    // First, we declare an HMM that we can use during EM
    HMM<TDistribution> new_hmm;
    new_hmm.Init(n_states_, n_dims_, type_, min_variance_, n_components_);

    // recycling is good so let's use these repeatedly
    Vector new_hmm_p_transition_denom;
    new_hmm_p_transition_denom.Init(n_states_);

    Vector gaussian_denom;
    if(type_ == GAUSSIAN) {
      gaussian_denom.Init(n_states_);
    }
    else {
      gaussian_denom.Init(0);
    }

    Vector weight_qi;
    if(type_ == MIXTURE) {
      weight_qi.Init(n_states_);
    }
    else {
      weight_qi.Init(0);
    }


    double last_total_neg_likelihood = std::numeric_limits<double>::max();
    double current_total_neg_likelihood = 0; // an irrelevant assignment

    int iteration_num = 0;
    bool converged = false;

    while(!converged) {
      printf("iteration %d\n", iteration_num);
      iteration_num++;
      
      new_hmm.p_initial.SetZero();
      new_hmm.p_transition.SetZero();
      new_hmm_p_transition_denom.SetZero();
      
      for(int i = 0; i < n_states_; i++) {
	new_hmm.state_distributions[i].SetZero();
      }

      if(type_ == GAUSSIAN) {
	gaussian_denom.SetZero();
      }
      else if(type_ == MIXTURE) {
	weight_qi.SetZero();
      }
      
      current_total_neg_likelihood = 0;
      for(int m = 0; m < n_sequences; m++) {
	const GenMatrix<T> &sequence = sequences[m];
	int sequence_length = sequence.n_cols();

	Matrix p_x_given_q; // Rabiner's b
	
	ArrayList<Matrix> p_x_given_mixture_q; // P_{q_{i,k}}(x_t)/P_{q_i}(x_t)
	ArrayList<Matrix> p_qq_t; // Rabiner's xi = P(q_t, q_{t+1} | X)
	Matrix p_qt; // Rabiner's gamma = P(q_t | X)
	double neg_likelihood = 1;

	PrintDebug("current HMM");
	ExpectationStep(sequence,
			&p_x_given_q, &p_x_given_mixture_q,
			&p_qq_t, &p_qt,
			&neg_likelihood);
	
	p_x_given_q.PrintDebug("p_x_given_q");
	if(type_ == MIXTURE) {
	  p_x_given_mixture_q[0].PrintDebug("p_x_given_mixture_q");
	}
	p_qt.PrintDebug("p_qt");
	
	current_total_neg_likelihood += neg_likelihood;
      

	/////////////////////////////
	// M STEP
	/////////////////////////////
     
	// ACCUMULATE
       
	// accumulate initial state probabilities
	for(int i = 0; i < n_states_; i++) {
	  new_hmm.p_initial[i] += p_qt.get(0, i);
	}
      
	// accumulate state transition probabilities
	for(int i = 0; i < n_states_; i++) {
	  for(int t = 0; t < sequence_length - 1; t++) {
	    for(int j = 0; j < n_states_; j++) {
	      // Note that new_hmm.p_transition is treated as its transpose
	      // initially for efficiency. We transpose it at the end of
	      // its computation.
	      new_hmm.p_transition.set(j, i,
				       new_hmm.p_transition.get(j, i)
				       + p_qq_t[i].get(j, t));
	    }
	    new_hmm_p_transition_denom[i] += p_qt.get(t, i); 
	  }
	}

	// accumulate density statistics for observables
	if(type_ == MULTINOMIAL) {
	  for(int i = 0; i < n_states_; i++) {
	    for(int t = 0; t < sequence_length; t++) {
	      GenVector<T> x_t;
	      sequence.MakeColumnVector(t, &x_t);
	      new_hmm.state_distributions[i].Accumulate(p_qt.get(t, i), x_t,
							0);
	    }
	  }
	}
	else if(type_ == GAUSSIAN) {
	  for(int i = 0; i < n_states_; i++) {
	    for(int t = 0; t < sequence_length; t++) {
	      GenVector<T> x_t;
	      sequence.MakeColumnVector(t, &x_t);
	      new_hmm.state_distributions[i].Accumulate(p_qt.get(t, i), x_t,
							0);
	      // keep track of normalization factor
	      gaussian_denom[i] += p_qt.get(t, i);
	    }
	  }
	}
	else if(type_ == MIXTURE) {
	  for(int k = 0; k < n_components_; k++) {
	    printf("accumulating component %d\n", k);
	    for(int i = 0; i < n_states_; i++) {
	      for(int t = 0; t < sequence_length; t++) {
		GenVector<T> x_t;
		sequence.MakeColumnVector(t, &x_t);

		// hopefully p_x_given_mixture_q[k].get(i,t) is fast since
		// n_states_ is usually small (< 20)
		double scaling_factor =
		  p_qt.get(t, i) * p_x_given_mixture_q[k].get(i, t);
		
		new_hmm.state_distributions[i].Accumulate(scaling_factor, x_t,
							  k);
	      }
	    }
	    printf("done accumulating component %d\n", k);
	  }
	  for(int i = 0; i < n_states_; i++) {
	    // note that new_hmm_p_transition_denom[i] =
	    //             \sum_{t = 0 -> T - 2} p_qt.get(t, i)
	    weight_qi[i] +=
	      new_hmm_p_transition_denom[i] + p_qt.get(sequence_length - 1, i);
	    // so, weight_qi[i] = \sum_{t = 0 -> T - 1} p_qt.get(t, i)
	  }
	} //end if(MIXTURE)
      } // end for(all sequences)
      printf("current_total_neg_likelihood = %f\n",
	     current_total_neg_likelihood);


      // NORMALIZE - control NaN risk!

      weight_qi.PrintDebug("weight_qi");

      // normalize initial state probabilities
      // no risk - Sum must be positive
      la::Scale(((double)1) / Sum(new_hmm.p_initial),
		&(new_hmm.p_initial));

      //new_hmm_p_transition_denom.PrintDebug("new_hmm_p_transition_denom");
      // normalize state transition probabilities
      // should be no risk - handled zero state weight case
      for(int i = 0; i < n_states_; i++) {
	// Again, Note that new_hmm.p_transition is treated as its transpose
	// initially for efficiency. We transpose it at the end of
	// its computation (below).

	// if state i isn't visited, set its transition probs to uniform
	if(new_hmm_p_transition_denom[i] == 0) {
	  double one_over_n_states = ((double)1) / ((double)n_states_);
	  for(int j = 0; j < n_states_; j++) {
	    new_hmm.p_transition.set(j, i, one_over_n_states);
	  }
	}
	else {
	  for(int j = 0; j < n_states_; j++) {
	    new_hmm.p_transition.set(j, i,
				     new_hmm.p_transition.get(j, i)
				     / new_hmm_p_transition_denom[i]);
	  }
	}
      }
      la::TransposeSquare(&(new_hmm.p_transition));

      // normalize density statistics for observables
      // should be no risk - took care of cases where states carry no weight
      // by using the same distribution parameters for those states as they
      // had in the previous iteration.
      if(type_ == MULTINOMIAL) {
	for(int i = 0; i < n_states_; i++) {
	  new_hmm.state_distributions[i].Normalize(0, state_distributions[i]);
	}
      }
      else if(type_ == GAUSSIAN) {
	for(int i = 0; i < n_states_; i++) {
	  new_hmm.state_distributions[i].Normalize(gaussian_denom[i],
						   state_distributions[i]);
	}
      }
      else if(type_ == MIXTURE) {
	for(int i = 0; i < n_states_; i++) {
	  new_hmm.state_distributions[i].Normalize(weight_qi[i],
						   state_distributions[i]);
	}
      }

      SwapHMMParameters(&new_hmm);
  
      // How far have we come? Have we converged?
      double improvement_total_neg_likelihood =
	last_total_neg_likelihood - current_total_neg_likelihood;
      printf("improvement = %e\n", improvement_total_neg_likelihood);
      if(improvement_total_neg_likelihood < neg_likelihood_threshold) {
	converged = true;
      }
      else if(iteration_num > max_iterations) {
	converged = true;
      }
      else {
	last_total_neg_likelihood = current_total_neg_likelihood;
      }
    } // end while(!converged)

    printf("converged after %d iterations\n", iteration_num);

    //new_hmm is one iteration lesser than 'this' but it matches current_total_neg_likelihood, so we'll use it instead
    SwapHMMParameters(&new_hmm);
  }
  
  template<typename T>
  void Viterbi(const GenMatrix<T> &sequence,
	       double* p_neg_ll,
	       Vector* p_best_path) {
    double &neg_ll = *p_neg_ll;
    Vector &best_path = *p_best_path;
    
    int sequence_length = sequence.n_cols();

    Matrix p_x_given_q;
    ComputePxGivenQ(sequence, &p_x_given_q);
    
    Matrix logp_path;
    logp_path.Init(n_states_, sequence_length);
    
    Matrix best_into;
    best_into.Init(n_states_, sequence_length);
    
    Matrix logp_transition;
    logp_transition.Init(n_states_, n_states_);
    for(int j = 0; j < n_states; j++) {
      for(int i = 0; i < n_states; i++) {
	logp_transition.set(i, j,
			    log(p_transition.get(i, j)));
      }
    }
    
    for(int i = 0; i < n_states_; i++) {
      logp_path.set(i, 0,
		    log(p_initial[i]) + log(p_x_given_q.get(i, 0)));
      best_into.set(i, 0,
		    0);
    }

    for(int t = 1; t < sequence_length; t++) {
      Vector logp_path_t_minus_1;
      logp_path.MakeColumnVector(t - 1, &logp_path_t_minus_1);
	
      for(int j = 0; j < n_states_; j++) {
	Vector logp_transition_to_j;
	logp_transition.MakeColumnVector(j, &logp_transition_to_j);
	  
	double max;
	int argmax;
	MaxLogProduct(logp_path_t_minus_1, logp_transition_to_j,
		      &max, &argmax);
	logp_path.set(j, t,
		      max + log(p_x_given_q.get(j, t)));
	best_into.set(j, t,
		      argmax);
      }
    }

    best_path.Init(sequence_length);
      
    Vector logp_path_T_minus_1;
    logp_path.MakeColumnVector(sequence_length - 1, &logp_path_T_minus_1);
    double max;
    int argmax;
    Max(logp_path_T_minus_1, &max, &argmax);
    best_path[sequence_length - 1] = argmax;
    neg_ll = -logp_path.get(argmax, sequence_length - 1);

    for(int t = sequence_length - 1; t >= 1; t++) {
      best_path[t - 1] = best_into.get(best_path[t], t);
    }

  }


  void Max(const Vector &x, double* p_max, int* p_argmax) {
    double &max = *p_max;
    int &argmax = *p_argmax;

    max = -std::numeric_limits<double>::max();
    argmax = -1;

    int set_size = x.length();
    for(int i = 0; i < set_size; i++) {
      if(x[i] > max) {
	max = x[i];
	argmax = i;
      }
    }
  }


  void MaxProduct(const Vector &x, const Vector &y,
		  double* p_max, int* p_argmax) {
    double &max = *p_max;
    int &argmax = *p_argmax;

    max = -std::numeric_limits<double>::max();
    argmax = -1;

    int set_size = x.length();
    for(int i = 0; i < set_size; i++) {
      double value = x[i] * y[i];
      if(value > max) {
	max = value;
	argmax = i;
      }
    }
  }


  void MaxLogProduct(const Vector &x, const Vector &y,
		     double* p_max, int* p_argmax) {
    double &max = *p_max;
    int &argmax = *p_argmax;
    
    max = -std::numeric_limits<double>::max();
    argmax = -1;
    
    int set_size = x.length();
    for(int i = 0; i < set_size; i++) {
      double value = x[i] + y[i];
      if(value > max) {
	max = value;
	argmax = i;
      }
    }
  }
    



    
  



  void SetStateDistribution(int i,
			    const TDistribution &distribution) {
    state_distributions[i].CopyValues(distribution);
  }


  // accessors

  int n_states() const {
    return n_states_;
  }

  int n_dims() const {
    return n_dims_;
  }
  /*
  Vector p_initial() const {
    return p_initial;
  }

  Matrix p_transition() const {
    return p_transition;
  }
  
  TDistribution* state_distributions() const {
    return state_distributions_;
  }
  */
  void PrintDebug(const char *name = "", FILE *stream = stderr) const {
    fprintf(stream, "----- HMM %s ------\n", name);
    
    p_initial.PrintDebug("initial probabilities", stream);
    p_transition.PrintDebug("transition probabilities", stream);

    char string[100];    
    for(int i = 0 ;i < n_states_; i++) {
      sprintf(string, "state %d:\n", i+1);
      state_distributions[i].PrintDebug(string);
      fprintf(stream, "\n");
    }
  }

  void SetPInitial(Vector p_initial_in) {
    p_initial.CopyValues(p_initial_in);
  }

  void SetPTransition(Matrix p_transition_in) {
    p_transition.CopyValues(p_transition_in);
  }
  

  ~HMM() {
    //printf("destroying HMM\n");
    Destruct();
  }

  void Destruct() {
    for(int i = 0; i < n_states_; i++) {
      state_distributions[i].Destruct();
    }
    free(state_distributions);
  }

};





#endif /* HMM_H */

