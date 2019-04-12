/*
 * (c) Copyright 2018 by Coinkite Inc. This file is part of Coldcard <coldcardwallet.com>
 * and is covered by GPLv3 license found in COPYING.
 */

#define MICROPY_HW_BOARD_NAME       "Coldcard"
#define MICROPY_PY_SYS_PLATFORM     "coldcard"

#define MICROPY_HW_MCU_NAME         "STM32L475RG"

#define MICROPY_HW_HAS_SWITCH       (0)
#define MICROPY_HW_HAS_FLASH        (1)
#define MICROPY_HW_HAS_SDCARD       (1)
#define MICROPY_HW_HAS_LCD          (0)
#define MICROPY_HW_ENABLE_RTC       (0)
#define MICROPY_HW_ENABLE_HW_I2C    (0)

#define HSE_VALUE    ((uint32_t)8000000) /*!< Value of the External oscillator in Hz */

// USB config
#define MICROPY_HW_ENABLE_USB (1)
#define MICROPY_HW_USB_FS (1)

// HSE is used and is 8MHz
// see hardcoding in clocks.c

#define MICROPY_HW_CLK_PLLN (40)
#define MICROPY_HW_CLK_PLLM (2)
#define MICROPY_HW_CLK_PLLR (2)
#define MICROPY_HW_CLK_PLLP (7)
#define MICROPY_HW_CLK_PLLQ (4)

#define MICROPY_HW_FLASH_LATENCY    FLASH_LATENCY_4

// UART config
#define MICROPY_HW_UART4_TX     (pin_A0)
#define MICROPY_HW_UART4_RX     (pin_A0)
#define MICROPY_HW_UARTn_IS_HALF_DUPLEX(n)    ((n) == 4)


// no I2C at all

/*
#define MICROPY_HW_UART_REPL        PYB_UART_2
#define MICROPY_HW_UART_REPL_BAUD   115200

// I2C busses
#define MICROPY_HW_I2C1_SCL (pin_B6)
#define MICROPY_HW_I2C1_SDA (pin_B7)
#define MICROPY_HW_I2C2_SCL (pin_B10)
#define MICROPY_HW_I2C2_SDA (pin_B11)
#define MICROPY_HW_I2C3_SCL (pin_C0)
#define MICROPY_HW_I2C3_SDA (pin_C1)
*/

// SPI busses (two)
//#define MICROPY_HW_SPI1_NSS     (pin_A4)
#define MICROPY_HW_SPI1_SCK     (pin_A5)
//#define MICROPY_HW_SPI1_MISO    (pin_A6)
#define MICROPY_HW_SPI1_MOSI    (pin_A7)

#define MICROPY_HW_SPI2_NSS     (pin_B9)
#define MICROPY_HW_SPI2_SCK     (pin_B10)
#define MICROPY_HW_SPI2_MISO    (pin_C2)
#define MICROPY_HW_SPI2_MOSI    (pin_C3)

/*
// USRSW is pulled low. Pressing the button makes the input go high.
#define MICROPY_HW_USRSW_PIN        (pin_C13)
#define MICROPY_HW_USRSW_PULL       (GPIO_NOPULL)
#define MICROPY_HW_USRSW_EXTI_MODE  (GPIO_MODE_IT_FALLING)
#define MICROPY_HW_USRSW_PRESSED    (0)

// LEDs
#define MICROPY_HW_LED1             (pin_A5) // Green LD2 LED on Nucleo
#define MICROPY_HW_LED_ON(pin)      (mp_hal_pin_high(pin))
#define MICROPY_HW_LED_OFF(pin)     (mp_hal_pin_low(pin))
*/

// SD card detect switch
// - open when card inserted, grounded when no card
#define MICROPY_HW_SDCARD_DETECT_PIN        (pin_A9)
#define MICROPY_HW_SDCARD_DETECT_PULL       (GPIO_PULLUP)
#define MICROPY_HW_SDCARD_DETECT_PRESENT    (GPIO_PIN_SET)


// We have our own version of this code.
#define MICROPY_HW_ENABLE_RNG       (0)

extern void ckcc_early_init(void);
#define MICROPY_BOARD_EARLY_INIT        ckcc_early_init

// Pull in lots of crypto stuff
#define MICROPY_PY_TREZORCRYPTO     (1)

// Need CRC32 for 7z support.
#define MICROPY_PY_UBINASCII_CRC32  (1)

// Experiment, works.
//#define MICROPY_STACKLESS       (1)

#define USBD_MANUFACTURER_STRING      "Coinkite"
#define USBD_PRODUCT_HS_STRING        "Coldcard Wallet"
#define USBD_PRODUCT_FS_STRING        "Coldcard Wallet"
#define USBD_CONFIGURATION_HS_STRING  "HS Config"
#define USBD_INTERFACE_HS_STRING      "HS Interface"
#define USBD_CONFIGURATION_FS_STRING  "FS Config"
#define USBD_INTERFACE_FS_STRING      "FS Interface"
