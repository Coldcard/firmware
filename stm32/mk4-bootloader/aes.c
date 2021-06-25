/*
 * (c) Copyright 2021 by Coinkite Inc. This file is covered by license found in COPYING-CC.
 */
#include "basics.h"
#include "console.h"
#include "aes.h"
#include "stm32l4xx_hal.h"
#include "constant_time.h"
#include <string.h>

// aes_init()
//
    void
aes_init(AES_CTX *ctx)
{
    memset(ctx, 0, sizeof(AES_CTX));
}

// aes_add()
//
// - capture more data to be encrypted/decrypted
//
    void
aes_add(AES_CTX *ctx, const uint8_t data_in[], uint32_t len)
{
    memcpy(ctx->pending+ctx->num_pending, data_in, len);
    ctx->num_pending += len;
    ASSERT(ctx->num_pending < sizeof(ctx->pending));
}

// aes_done()
//
// Do the decryption.
//
    void
aes_done(AES_CTX *ctx, uint8_t data_out[], uint32_t len, const uint8_t key[32], const uint8_t nonce[AES_BLOCK_SIZE])
{
    ASSERT(len <= ctx->num_pending);

    // wake up block
    __HAL_RCC_AES_CLK_ENABLE();

    ctx->hh.Instance = AES;
    ctx->hh.Init.DataType = CRYP_DATATYPE_8B;
    ctx->hh.Init.KeySize = CRYP_KEYSIZE_256B;
    ctx->hh.Init.OperatingMode = CRYP_ALGOMODE_ENCRYPT;
    ctx->hh.Init.ChainingMode = CRYP_CHAINMODE_AES_CTR;
    ctx->hh.Init.KeyWriteFlag = CRYP_KEY_WRITE_ENABLE;       // we want to set key now

    ctx->hh.Init.pKey = (uint8_t *)key;
    ctx->hh.Init.pInitVect = (uint8_t *)nonce;

    HAL_StatusTypeDef rv = HAL_CRYP_Init(&ctx->hh);
    ASSERT(rv == HAL_OK); 


    //__HAL_CRYP_DISABLE(hcryp);

    // HAL code will happy work past end of provided area, up to the block size.
    rv = HAL_CRYPEx_AES(&ctx->hh, ctx->pending, len, ctx->pending, HAL_MAX_DELAY);
    ASSERT(rv == HAL_OK); 

    memcpy(data_out, ctx->pending, len);

    memset(ctx, 0, sizeof(AES_CTX));

    // reset state of chip block, and leave clock off as well
    __HAL_RCC_AES_CLK_ENABLE();
    __HAL_RCC_AES_FORCE_RESET();
    __HAL_RCC_AES_RELEASE_RESET();
    __HAL_RCC_AES_CLK_DISABLE();
}


#ifndef RELEASE
// aes_selftest()
//
    void
aes_selftest(void)
{
    puts2("AES selftest: ");

/*
    >>> import pyaes
    >>> pyaes.AESModeOfOperationCTR(bytes(32), pyaes.Counter(0)).encrypt(b'Zack')
    b'\x86\xf4\xa3\x13'
*/

    AES_CTX ctx;
    static const uint8_t key[32] = { };
    static const uint8_t nonce[16] = { };
    static const uint8_t msg[4] = "Zack";
    static const uint8_t expect[4] = { 0x86, 0xf4, 0xa3, 0x13 };

    uint8_t tmp[4];

    aes_init(&ctx);
    aes_add(&ctx, msg, 4);
    aes_done(&ctx, tmp, 4, key, nonce);
    ASSERT(check_equal(tmp, expect, 4));

    aes_init(&ctx);
    aes_add(&ctx, expect, 4);
    aes_done(&ctx, tmp, 4, key, nonce);
    ASSERT(check_equal(tmp, msg, 4));

    puts("PASS");
}
#endif

//
//
// Junk from stm32l4xx_hal_cryp_ex.c below.
//
//

/**
  * @brief  Handle CRYP hardware block Timeout when waiting for CCF flag to be raised.
  * @param  hcryp pointer to a CRYP_HandleTypeDef structure that contains
  *         the configuration information for CRYP module.
  * @param  Timeout Timeout duration.
  * @retval HAL status
  */
static HAL_StatusTypeDef CRYP_WaitOnCCFlag(CRYP_HandleTypeDef const * const hcryp, uint32_t Timeout)
{
  uint32_t tickstart;

  /* Get timeout */
  tickstart = HAL_GetTick();

  while(HAL_IS_BIT_CLR(hcryp->Instance->SR, AES_SR_CCF))
  {
    /* Check for the Timeout */
    if(Timeout != HAL_MAX_DELAY)
    {
      if((HAL_GetTick() - tickstart ) > Timeout)
      {
        return HAL_TIMEOUT;
      }
    }
  }
  return HAL_OK;
}


/**
  * @brief  Read derivative key in polling mode when CRYP hardware block is set
  *         in key derivation operating mode (mode 2).
  * @param  hcryp pointer to a CRYP_HandleTypeDef structure that contains
  *         the configuration information for CRYP module.
  * @param  Output Pointer to the returned buffer.
  * @param  Timeout Specify Timeout value.
  * @retval HAL status
  */
static HAL_StatusTypeDef CRYP_ReadKey(CRYP_HandleTypeDef *hcryp, uint8_t* Output, uint32_t Timeout)
{
  uint32_t outputaddr = (uint32_t)Output;

  /* Wait for CCF flag to be raised */
  if(CRYP_WaitOnCCFlag(hcryp, Timeout) != HAL_OK)
  {
    hcryp->State = HAL_CRYP_STATE_READY;
    __HAL_UNLOCK(hcryp);
    return HAL_TIMEOUT;
  }
  /* Clear CCF Flag */
  __HAL_CRYP_CLEAR_FLAG(hcryp, CRYP_CCF_CLEAR);

    /* Read the derivative key from the AES_KEYRx registers */
  if (hcryp->Init.KeySize == CRYP_KEYSIZE_256B)
  {
    *(uint32_t*)(outputaddr) = __REV(hcryp->Instance->KEYR7);
    outputaddr+=4U;
    *(uint32_t*)(outputaddr) = __REV(hcryp->Instance->KEYR6);
    outputaddr+=4U;
    *(uint32_t*)(outputaddr) = __REV(hcryp->Instance->KEYR5);
    outputaddr+=4U;
    *(uint32_t*)(outputaddr) = __REV(hcryp->Instance->KEYR4);
    outputaddr+=4U;
  }

    *(uint32_t*)(outputaddr) = __REV(hcryp->Instance->KEYR3);
    outputaddr+=4U;
    *(uint32_t*)(outputaddr) = __REV(hcryp->Instance->KEYR2);
    outputaddr+=4U;
    *(uint32_t*)(outputaddr) = __REV(hcryp->Instance->KEYR1);
    outputaddr+=4U;
    *(uint32_t*)(outputaddr) = __REV(hcryp->Instance->KEYR0);


  /* Return function status */
  return HAL_OK;
}


/**
  * @brief  Write/read input/output data in polling mode.
  * @param  hcryp pointer to a CRYP_HandleTypeDef structure that contains
  *         the configuration information for CRYP module.
  * @param  Input Pointer to the Input buffer.
  * @param  Ilength Length of the Input buffer in bytes, must be a multiple of 16.
  * @param  Output Pointer to the returned buffer.
  * @param  Timeout Specify Timeout value.
  * @retval HAL status
  */
static HAL_StatusTypeDef CRYP_ProcessData(CRYP_HandleTypeDef *hcryp, uint8_t* Input, uint16_t Ilength, uint8_t* Output, uint32_t Timeout)
{
  uint32_t index;
  uint32_t inputaddr  = (uint32_t)Input;
  uint32_t outputaddr = (uint32_t)Output;


  for(index=0U ; (index < Ilength); index += 16U)
  {
    /* Write the Input block in the Data Input register */
    hcryp->Instance->DINR = *(uint32_t*)(inputaddr);
    inputaddr+=4U;
    hcryp->Instance->DINR = *(uint32_t*)(inputaddr);
    inputaddr+=4U;
    hcryp->Instance->DINR  = *(uint32_t*)(inputaddr);
    inputaddr+=4U;
    hcryp->Instance->DINR = *(uint32_t*)(inputaddr);
    inputaddr+=4U;

    /* Wait for CCF flag to be raised */
    if(CRYP_WaitOnCCFlag(hcryp, Timeout) != HAL_OK)
    {
      hcryp->State = HAL_CRYP_STATE_READY;
      __HAL_UNLOCK(hcryp);
      return HAL_TIMEOUT;
    }

    /* Clear CCF Flag */
    __HAL_CRYP_CLEAR_FLAG(hcryp, CRYP_CCF_CLEAR);

    /* Read the Output block from the Data Output Register */
    *(uint32_t*)(outputaddr) = hcryp->Instance->DOUTR;
    outputaddr+=4U;
    *(uint32_t*)(outputaddr) = hcryp->Instance->DOUTR;
    outputaddr+=4U;
    *(uint32_t*)(outputaddr) = hcryp->Instance->DOUTR;
    outputaddr+=4U;
    *(uint32_t*)(outputaddr) = hcryp->Instance->DOUTR;
    outputaddr+=4U;

    /* If the suspension flag has been raised and if the processing is not about
       to end, suspend processing */
    if ((hcryp->SuspendRequest == HAL_CRYP_SUSPEND) && ((index+16U) < Ilength))
    {
      /* Reset SuspendRequest */
      hcryp->SuspendRequest = HAL_CRYP_SUSPEND_NONE;

      /* Save current reading and writing locations of Input and Output buffers */
      hcryp->pCrypOutBuffPtr =  (uint8_t *)outputaddr;
      hcryp->pCrypInBuffPtr  =  (uint8_t *)inputaddr;
      /* Save the number of bytes that remain to be processed at this point */
      hcryp->CrypInCount     =  Ilength - (index+16U);

      /* Change the CRYP state */
      hcryp->State = HAL_CRYP_STATE_SUSPENDED;

      return HAL_OK;
    }


  }
  /* Return function status */
  return HAL_OK;

}



/**
  * @brief  Carry out in polling mode the ciphering or deciphering operation according to
  *         hcryp->Init structure fields, all operating modes (encryption, key derivation and/or decryption) and
  *         chaining modes ECB, CBC and CTR are managed by this function in polling mode.
  * @param  hcryp pointer to a CRYP_HandleTypeDef structure that contains
  *         the configuration information for CRYP module
  * @param  pInputData Pointer to the plain text in case of encryption or cipher text in case of decryption
  *                     or key derivation+decryption.
  *                     Parameter is meaningless in case of key derivation.
  * @param  Size Length of the input data buffer in bytes, must be a multiple of 16.
  *               Parameter is meaningless in case of key derivation.
  * @param  pOutputData Pointer to the cipher text in case of encryption or plain text in case of
  *                     decryption/key derivation+decryption, or pointer to the derivative keys in
  *                     case of key derivation only.
  * @param  Timeout Specify Timeout value
  * @retval HAL status
  */
HAL_StatusTypeDef HAL_CRYPEx_AES(CRYP_HandleTypeDef *hcryp, uint8_t *pInputData, uint16_t Size, uint8_t *pOutputData, uint32_t Timeout)
{

  if (hcryp->State == HAL_CRYP_STATE_READY)
  {
    /* Check parameters setting */
    if (hcryp->Init.OperatingMode == CRYP_ALGOMODE_KEYDERIVATION)
    {
      if (pOutputData == NULL)
      {
        return  HAL_ERROR;
      }
    }
    else
    {
      if ((pInputData == NULL) || (pOutputData == NULL) || (Size == 0U))
      {
        return  HAL_ERROR;
      }
    }

    /* Process Locked */
    __HAL_LOCK(hcryp);

    /* Change the CRYP state */
    hcryp->State = HAL_CRYP_STATE_BUSY;

    /* Call CRYP_ReadKey() API if the operating mode is set to
       key derivation, CRYP_ProcessData() otherwise  */
    if (hcryp->Init.OperatingMode == CRYP_ALGOMODE_KEYDERIVATION)
    {
      if(CRYP_ReadKey(hcryp, pOutputData, Timeout) != HAL_OK)
      {
        return HAL_TIMEOUT;
      }
    }
    else
    {
      if(CRYP_ProcessData(hcryp, pInputData, Size, pOutputData, Timeout) != HAL_OK)
      {
        return HAL_TIMEOUT;
      }
    }

    /* If the state has not been set to SUSPENDED, set it to
       READY, otherwise keep it as it is */
    if (hcryp->State != HAL_CRYP_STATE_SUSPENDED)
    {
      hcryp->State = HAL_CRYP_STATE_READY;
    }

    /* Process Unlocked */
    __HAL_UNLOCK(hcryp);

    return HAL_OK;
  }
  else
  {
    return HAL_BUSY;
  }
}




// EOF
