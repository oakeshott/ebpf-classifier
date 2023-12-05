/*******************************************************************
@file mlp.h
 *  @brief Function prototypes to create and run an MLP for inference
 *  with only integers (8-bit integers and 32-bit integers
 *  in fixed-point)
 *
 *  @author Benjamin Fuhrer
 *
*******************************************************************/
#ifndef MLP_H
#define MLP_H

// void run_mlp(const int64_t *x, const unsigned int N, unsigned int *class_indices);
void run_mlp(const int64_t *x, const unsigned int N, unsigned int *class_indices,
    const int layer_1_s_x, const int layer_2_s_x, const int layer_3_s_x,
    const int layer_1_s_x_inv, const int layer_2_s_x_inv, const int layer_3_s_x_inv,
    const int *layer_1_s_w_inv, const int *layer_2_s_w_inv, const int *layer_3_s_w_inv,
    const int8_t *layer_1_weight, int8_t *layer_2_weight, int8_t *layer_3_weight);
/**
 * @brief Function to run an mlp for classification
 * 
 * @param x - NxK input matrix
 * @param N
 * @param class_indices - Nx1 vector for storing class index prediction
 */


#endif 
