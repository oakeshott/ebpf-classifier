/*******************************************************************
@file nn_math.h
 *  @brief Function prototypes for mathematical functions
 *
 *
 *  @author Benjamin Fuhrer
 *
*******************************************************************/
#ifndef NN_MATH_H
#define NN_MATH_H

#define MAX(a,b) (((a)>(b))?(a):(b))
#define MIN(a,b) (((a)<(b))?(a):(b))

#define NUM_BITS 8
#define INT8_MAX_VALUE 127
#define INT16_MAX_VALUE 32767
#define FXP_VALUE 16
#define ROUND_CONST (1 << (FXP_VALUE - 1)) // = 0.5 to before right shifting to improve rounding
// #define DEBUG_MODE
#ifdef DEBUG_MODE
#include <stdio.h>
#endif

#include <stdint.h>
int64_t fxp_mult_by_parts_with_round(int8_t fxp_a, int8_t fxp_b);

void mat_mult(const int8_t *mat_l, const int8_t *mat_r, int64_t *result, const unsigned int N, const unsigned int K, const unsigned int  M);
/**
 * @brief Calculates matrix multiplication as: Y = XW
 *  
 * 
 * @param mat_l - left matrix (X), size NxK
 * @param mat_r - right matrix (W), size (K+1)xM, the last row of W contains the bias vector
 * @param result - output matrix (Y), size NxM
 * @param N - number of rows in X
 * @param K - number of columns/rows in X/W
 * @param M - number of columns in W
 * @return Void
 */

void relu(int64_t *tensor_in, const unsigned int size);
/**
 * @brief ReLU activation function
 * 
 * @param tensor_in - input tensor
 * @param size - size of flattened tensor
 * @return Void
 */

void sigmoid(int64_t *tensor, const unsigned int size);

void quantize(const int64_t *tensor_in, int8_t *tensor_q, const int scale_factor,
              const int scale_factor_inv, const unsigned int size);
/**
 * @brief Scale quantization of a tensor by a single amax value
 * 
 * @param tensor_in - input tensor
 * @param tensor_q - output quantized tensor
 * @param scale_factor - 127 / amax
 * @param scale_factor_inv - 1 / scale_factor
 * @param size - size of flattened tensor
 * @return Void
 */

void dequantize_per_row(int64_t *mat_in, const int *scale_factor_w_inv, const int scale_factor_x_inv, const unsigned int  N, const unsigned int  M);
/**
 * @brief Scale dequantization with per-row granulity
 * Each row is multiplied by the corresponding column amax value
 * offline calculate reciprocal(amax) so we can replace division by multiplication
 * 
 * @param mat_in - NxM input matrix to dequantize
 * @param scale_factor_w_inv -1XM row vector of layer's weight matrix scale factor values
 * @param scale_factor_x_inv - input inverse scale factor
 * @param N
 * @param M
 * @return Void
*/

void argmax_over_cols(const int64_t *mat_in, unsigned int *indices, const unsigned int N, const unsigned int M);
/**
 * @brief Calculate argmax per columns of an NxM matrix
 * 
 * @param mat_in - NxM input matrix
 * @param indices - 1xM indices to store argmax of each column
 * @param N
 * @param M
 * @return Void
 */


#endif //

