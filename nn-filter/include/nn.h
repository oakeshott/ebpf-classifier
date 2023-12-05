/*******************************************************************
@file nn.h
 *  @brief Function prototypes for neural network layers
 *
 *
 *  @author Benjamin Fuhrer
 *
*******************************************************************/
#ifndef NN_H
#define NN_H

#include <stdint.h>

void linear_layer(const int64_t *x, const int8_t *w, int64_t *output, const int x_scale_factor,
                  const int *w_scale_factor_inv, const int x_scale_factor_inv,
                  const unsigned int N,  const unsigned int K,
                  const unsigned int M, const unsigned int not_output_layer);
/**
 * @brief A neural network linear layer withthout bias  Y = ReLU(XW)
 *  x is quantized before multiplication with w and then dequantized per-row granulity prior to the activation function
 * 
 * @param x - NxK input matrix
 * @param w - KxM layer weight matrix
 * @param output - NxM output matrix
 * @param x_amax_quant - amax value for quantization of input matrix
 * @param x_w_amax_dequant - 1XM amax values for dequantization of Z=XW
 * @param N
 * @param K
 * @param M
 * @param hidden_layer - boolean value if layer is a hidden layer (activation)
 * 
 * @return Void
 */


#endif 

