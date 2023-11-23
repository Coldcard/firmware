/*
 * (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
 */

#define MICROPY_HW_BOARD_NAME       "Coldcard"
#define MICROPY_PY_SYS_PLATFORM     "coldcard"

#define MICROPY_HW_MCU_NAME         "STM32L4SxVI"

#define MICROPY_HW_HAS_SWITCH       (0)
#define MICROPY_HW_HAS_FLASH        (1)
#define MICROPY_HW_HAS_SDCARD       (1)
#define MICROPY_HW_HAS_LCD          (0)
#define MICROPY_HW_ENABLE_HW_I2C    (1)

// don't want, but lots of modules interdepend on this
#define MICROPY_HW_ENABLE_RTC       (0)

//#define HSE_VALUE    ((uint32_t)8000000) /*!< Value of the External oscillator in Hz */

// USB config
#define MICROPY_HW_ENABLE_USB (1)
#define MICROPY_HW_USB_FS (1)

// HSE is used and is 8MHz
// see hardcoding in clocks.c / bootrom / these values are not used / may be wrong
#define MICROPY_HW_CLK_PLLN (40)
#define MICROPY_HW_CLK_PLLM (2)
#define MICROPY_HW_CLK_PLLR (2)
#define MICROPY_HW_CLK_PLLP (7)
#define MICROPY_HW_CLK_PLLQ (4)

#define MICROPY_HW_FLASH_LATENCY    FLASH_LATENCY_4

// UART config
#define MICROPY_HW_UART4_TX     (pin_A0)
#define MICROPY_HW_UART4_RX     (pin_A0)
#define MICROPY_HW_UART2_TX     (pin_A2)
#define MICROPY_HW_UART2_RX     (pin_A3)
#define MICROPY_HW_UART1_TX     (pin_A9)
#define MICROPY_HW_UART1_RX     (pin_A10)

// Mk4 has real debug serial port, wonderful.
#define MICROPY_HW_UART_REPL        PYB_UART_1
#define MICROPY_HW_UART_REPL_BAUD   115200

/* I2C busses: 2 */
#define MICROPY_HW_I2C1_SCL (pin_B6)
#define MICROPY_HW_I2C1_SDA (pin_B7)
#define MICROPY_HW_I2C2_SCL (pin_B13)
#define MICROPY_HW_I2C2_SDA (pin_B14)
/*
#define MICROPY_HW_I2C3_SCL (pin_C0)
#define MICROPY_HW_I2C3_SDA (pin_C1)
*/

// SPI busses (one)
#define MICROPY_HW_SPI1_SCK     (pin_A5)
#define MICROPY_HW_SPI1_MOSI    (pin_A7)
//#define MICROPY_HW_SPI1_NSS     (pin_A4)
//#define MICROPY_HW_SPI1_MISO    (pin_A6)

/* removed in Mk4 rev B
#define MICROPY_HW_SPI2_NSS     (pin_B9)
#define MICROPY_HW_SPI2_SCK     (pin_B10)
#define MICROPY_HW_SPI2_MISO    (pin_C2)
#define MICROPY_HW_SPI2_MOSI    (pin_C3)
*/

// SD card detect switch
// - open when card inserted, grounded when no card
/* Q has dual slot, so multiple detect pins, this can't work
#define MICROPY_HW_SDCARD_DETECT_PIN        (pin_C13)
#define MICROPY_HW_SDCARD_DETECT_PULL       (GPIO_PULLUP)
#define MICROPY_HW_SDCARD_DETECT_PRESENT    (GPIO_PIN_SET)
*/


// We have our own version of this code.
#define MICROPY_HW_ENABLE_RNG       (0)

extern void ckcc_early_init(void);
#define MICROPY_BOARD_EARLY_INIT        ckcc_early_init

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

// Where the heap should end up.
extern void *ckcc_heap_start(void);
extern void *ckcc_heap_end(void);
#define MICROPY_HEAP_START      ckcc_heap_start()
#define MICROPY_HEAP_END        ckcc_heap_end()

// Features/or not.
#define MICROPY_HW_ENABLE_DHT       (0)
#define MICROPY_HW_ENABLE_ADC       (0)

// override some boot-up stuff
#define MICROPY_BOARD_BEFORE_BOOT_PY    ckcc_boardctrl_before_boot_py
#define MICROPY_BOARD_AFTER_BOOT_PY     ckcc_boardctrl_after_boot_py

struct _boardctrl_state_t;
extern void ckcc_boardctrl_before_boot_py(struct _boardctrl_state_t *state);
extern void ckcc_boardctrl_after_boot_py(struct _boardctrl_state_t *state);

#define MICROPY_HW_SDCARD_MOUNT_AT_BOOT         (0)

#define MICROPY_HW_ENABLE_SDCARD                (1)
#define MICROPY_HW_ENABLE_CARD_IDENT            (1)

// called from usb.c to setup customized MSC storage
struct _usbd_cdc_msc_hid_state_t;
extern void psramdisk_USBD_MSC_RegisterStorage(int num_lun, struct _usbd_cdc_msc_hid_state_t *usbd);
#define MICROPY_HW_CUSTOM_USB_MSC   psramdisk_USBD_MSC_RegisterStorage

// enable some code inside oofatfs that we need
#define FF_USE_FASTSEEK         (1)

// LEDs -- used for LCD backlight
#define MICROPY_HW_LED1             (pin_E3)
#define MICROPY_HW_LED_ON(pin)      (mp_hal_pin_high(pin))
#define MICROPY_HW_LED_OFF(pin)     (mp_hal_pin_low(pin))
#define MICROPY_HW_LED1_PWM         { TIM3, 3, TIM_CHANNEL_1, GPIO_AF2_TIM3 }

// EOF
