/*******************************************************************
@file mlp_params.h
*  @brief variable prototypes for model parameters and amax values
*
*
*  @author Benjamin Fuhrer
*
*******************************************************************/
#ifndef MLP_PARAMS
#define MLP_PARAMS

#define INPUT_DIM 12
#define H1 16
#define H2 16
//#define IS_BINARY
#ifdef IS_BINARY
#define OUTPUT_DIM 1
#else
#define OUTPUT_DIM 2
#endif
#include <stdint.h>


// quantization/dequantization constants
extern const int layer_1_s_x;
extern const int layer_1_s_x_inv;
extern const int layer_1_s_w_inv[16];
extern const int layer_2_s_x;
extern const int layer_2_s_x_inv;
extern const int layer_2_s_w_inv[16];
extern const int layer_3_s_x;
extern const int layer_3_s_x_inv;
extern const int layer_3_s_w_inv[2];
// Layer quantized parameters
extern const int8_t layer_1_weight[192];
extern const int8_t layer_2_weight[256];
extern const int8_t layer_3_weight[32];

#endif // end of MLP_PARAMS
