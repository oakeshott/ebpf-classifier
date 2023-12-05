
#include "nn_math.h"

int64_t fxp_mult_by_parts_with_round(int8_t fxp_a, int8_t fxp_b) {
  int64_t ret;
  int64_t int_a = fxp_a >> FXP_VALUE;
  int64_t frac_a = fxp_a - (int_a << FXP_VALUE);
  int64_t int_b = fxp_b >> FXP_VALUE;
  int64_t frac_b = fxp_b - (int_b << FXP_VALUE);

  ret = int_a * frac_b + int_b * frac_a;
  ret += (frac_a * frac_b + ((1 << FXP_VALUE) - 1)) >> FXP_VALUE;
  ret += (int_a * int_b) << FXP_VALUE;
  return ret;
}

void mat_mult(const int8_t *mat_l, const int8_t *mat_r, int64_t *result, const unsigned int N, const unsigned int K, const unsigned int M)
{
  unsigned int n, k, m;
  unsigned int row, col;
  int accumulator;
  /* int64_t accumulator_, accumulator_2; */

  for (m = 0; m < M; m++) {
    for (n = 0; n < N; n++) {
      row = n*K;
      accumulator = 0;
      for (k = 0; k < K; k++)
      {
        col = k*M;
        /* accumulator += fxp_mult_by_parts_with_round(mat_l[row + k], mat_r[col + m]); */
        /*  ORIGINAL */
        accumulator += mat_l[row + k] * mat_r[col + m];
      }
      result[n*M + m] = accumulator;
    }
  }
}


void relu(int64_t *tensor, const unsigned int size)
{
  unsigned int i;
  for (i = 0; i < size; i++) {
    tensor[i] = MAX(tensor[i], 0);
  }
}

void sigmoid(int64_t *tensor, const unsigned int size)
{
  unsigned int i;
  int eps = 1;
  for (i = 0; i < size; i++) {
    if (tensor[i] < -eps) {
      tensor[i] = 0;
    }
    else if (tensor[i] > eps) {
      tensor[i] = 1;
    }
    else {
      tensor[i] = tensor[i] / eps;
    }
  }
}

void quantize(const int64_t *tensor_in, int8_t *tensor_q, const int scale_factor,
    const int scale_factor_inv, const unsigned int size)
{
  unsigned int i;
  int rounded_value, tensor_int, tensor_frac;
  // separation to integer and fraction parts
  int scale_factor_int = (scale_factor + ROUND_CONST) >> FXP_VALUE;
  int scale_factor_frac = scale_factor - (scale_factor_int << FXP_VALUE);
  int overflow_threshold = INT8_MAX_VALUE*scale_factor_inv;
  // element wise operation - we iterate throughout the entire length of the flattened tensor
  /* printf("scale factor: %lld\t%lld\t%lld\t%lld\t%lld\t%lld\n", scale_factor, (scale_factor + ROUND_CONST), (scale_factor + ROUND_CONST) >> FXP_VALUE, scale_factor_int, scale_factor_frac, overflow_threshold); */
  for (i = 0; i < size; i++)
  {
    tensor_int = (tensor_in[i] + ROUND_CONST) >> FXP_VALUE;

/* #ifdef DEBUG_MODE */
/*     printf("%d\t%lld\t%d\t%d\t%d\n", i, tensor_in[i], tensor_int, scale_factor_inv, overflow_threshold); */
/* #endif */
    if (tensor_int > overflow_threshold)
      tensor_q[i] = (int8_t)INT8_MAX_VALUE;
    else if (tensor_int < -overflow_threshold)
      tensor_q[i] = -(int8_t)INT8_MAX_VALUE;
    else
    {
      tensor_frac = tensor_in[i] - (tensor_int << FXP_VALUE);
      // int * fxp = result is in fxp */
      rounded_value = tensor_int*scale_factor_frac + scale_factor_int*tensor_frac; 
      // fxp * fxp = fix-point multiplication with result is in fxp */
      rounded_value += (tensor_frac*scale_factor_frac + ROUND_CONST) >> FXP_VALUE; 
      // convert fxp to int and add to integer parts as final value should be a rounded integer
      rounded_value = ((rounded_value + ROUND_CONST) >> FXP_VALUE) + tensor_int*scale_factor_int; 

      tensor_q[i] = (int8_t)rounded_value; /* store quantized value in output tensor */
    }
  }
}


void dequantize_per_row(int64_t *mat_in, const int *scale_factor_w_inv, const int scale_factor_x_inv,
    const unsigned int  N, const unsigned int  M)
{
  unsigned int  k, n;

  int64_t out_value;


  for (n = 0; n < N; n++)
  {
    for (k = 0; k < M; k++)
    {

      out_value = scale_factor_w_inv[k] * scale_factor_x_inv;
      /* printf("%d\t%d\t%lld\t%lld\n", n, k, mat_in[n*M + k], out_value); */
      if (out_value > (1 << FXP_VALUE))
        mat_in[n*M + k] *= ((out_value + ROUND_CONST) >> FXP_VALUE);
      else
        mat_in[n*M + k] = (out_value*mat_in[n*M + k] + ROUND_CONST) >> FXP_VALUE;
      /* printf("%d\t%d\t%lld\t%lld\n", n, k, mat_in[n*M + k], out_value); */
    }
  }
}

void argmax_over_cols(const int64_t *mat_in, unsigned int *indices, const unsigned int N, const unsigned int M)
{

  // calculate max of each row
  unsigned int n, m, max_idx;
  int64_t row_max, value;
  for (n = 0; n < N; n++)
  {
    row_max = mat_in[n*M];
    max_idx = 0;
    for (m = 0; m < M; m++)
    {
      value = mat_in[n*M + m];
      if (value > row_max)
      {
        row_max = value;
        max_idx = m; // return column
      }
    }
    indices[n] = max_idx;
  }
}
