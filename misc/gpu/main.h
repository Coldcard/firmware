/*
 * (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
 */
#pragma once
#include "basics.h"

// note: USE_FULL_LL_DRIVER is defined in Makefile for all files.

#include "stm32c0xx.h"
#include "stm32c0xx_ll_bus.h"
#include "stm32c0xx_ll_gpio.h"
#include "stm32c0xx_ll_spi.h"

// Pins in use: be careful, most are also controlled by main micro
// - all on port A
#define PIN_G_CTRL        LL_GPIO_PIN_0
#define PIN_SCLK          LL_GPIO_PIN_1
#define PIN_MOSI          LL_GPIO_PIN_2
#define PIN_DATA_CMD      LL_GPIO_PIN_3
#define PIN_CS            LL_GPIO_PIN_4
#define PIN_TEAR          LL_GPIO_PIN_5

#define INPUT_PINS          (PIN_TEAR | PIN_G_CTRL)
#define SPI_PINS            (PIN_MOSI | PIN_SCLK)
#define OUTPUT_OD_PINS      (PIN_DATA_CMD | PIN_CS)

// EOF
