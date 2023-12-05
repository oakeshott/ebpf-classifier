/* #include "mlp_params.h" */
#include "nn.h"
#include "nn_math.h"
#include <stdint.h>

#define INPUT_DIM 12
#define H1 16
#define H2 16
//#define IS_BINARY
#ifdef IS_BINARY
#define OUTPUT_DIM 1
#else
#define OUTPUT_DIM 2
#endif
void run_mlp(const int64_t *x, const unsigned int N, unsigned int *class_indices,
    const int layer_1_s_x, const int layer_2_s_x, const int layer_3_s_x,
    const int layer_1_s_x_inv, const int layer_2_s_x_inv, const int layer_3_s_x_inv,
    const int *layer_1_s_w_inv, const int *layer_2_s_w_inv, const int *layer_3_s_w_inv,
    const int8_t *layer_1_weight, int8_t *layer_2_weight, int8_t *layer_3_weight
    ) {

  int64_t out_input[N*H1];
  linear_layer(x, layer_1_weight, out_input, layer_1_s_x,
      layer_1_s_w_inv, layer_1_s_x_inv,
      N, INPUT_DIM, H1, 1);
  int64_t out_h1[N*H2];
  linear_layer(out_input, layer_2_weight, out_h1, layer_2_s_x,
      layer_2_s_w_inv, layer_2_s_x_inv,
      N, H1, H2, 1);
  int64_t output[N*OUTPUT_DIM];
  linear_layer(out_h1, layer_3_weight, output, layer_3_s_x,
      layer_3_s_w_inv, layer_3_s_x_inv,
      N, H2, OUTPUT_DIM, 0);
  // get argmax
#ifdef IS_BINARY
  int j;
  for(j = 0; j < N; j++) {
    if (output[j] > 0) {
      class_indices[j] = 1;
    } else {
      class_indices[j] = 0;
    }
  }
#else
  argmax_over_cols(output, class_indices, N, OUTPUT_DIM);
#endif
}

