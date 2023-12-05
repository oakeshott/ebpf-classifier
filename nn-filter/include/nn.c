#include "nn.h"
#include "nn_math.h"

void linear_layer(const int64_t *x, const int8_t *w, int64_t *output, const int x_scale_factor,
                  const int *w_scale_factor_inv, const int x_scale_factor_inv,
                  const unsigned int  N, const unsigned int  K, const unsigned int  M,
                  const unsigned int  hidden_layer)
{
    int8_t x_q[N * K];
    quantize(x, x_q, x_scale_factor, x_scale_factor_inv,  N*K);

    mat_mult(x_q, w, output, N, K, M);
    dequantize_per_row(output, w_scale_factor_inv, x_scale_factor_inv, N, M);
    if (hidden_layer)
        relu(output, N*M);
    
}

