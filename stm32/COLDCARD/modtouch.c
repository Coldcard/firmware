/*
 * (c) Copyright 2018 by Coinkite Inc. This file is part of Coldcard <coldcardwallet.com>
 * and is covered by GPLv3 license found in COPYING.
 */

/* NOTES
    - this is controlling the TSC - Tcouh Sensing Controler
    - see lib/stm32lib/STM32L4xx_HAL_Driver/Inc/stm32l4xx_hal_tsc.h
    - probably-singleton style master object, handles all pins (up to 24)
    - there are (up to?) 8 groups, each with 4 pins associated
    - all groups can sample at once, but only a singe pin in each
    - one pin in each group is lost to a sense cap, so really 3 touch sensors per group
    - unused pins in the group will be floated or pulled low during acquision (caution)
    - in their terminlogy "sheild io" is the sense cap line.
    - example code: <https://github.com/eleciawhite/STM32Cube/blob/master/STM32Cube_FW_F3_V1.3.0/Projects/STM32373C_EVAL/Examples/TSC/TSC_BasicAcquisition_Interrupt/Src/main.c>
*/

#include <stdio.h>
#include <string.h>


#include "modtouch.h"
#include "rng.h"
#include "flash.h"
#include "py/gc.h"
#include "py/runtime.h"
#include "py/mphal.h"
#include "py/mperrno.h"

typedef struct _modtouch_obj_t {
    mp_obj_base_t base;

    // big object containing both init values and current state
    TSC_HandleTypeDef   hw;

    bool initialized;

    // using during interrupt only
    int8_t          group1, group2;
    uint16_t        result1, result2;

    mp_obj_t        handler;
} modtouch_obj_t;

// one instance can have an interrupt pending. "please" don't delete/free during that time.
static modtouch_obj_t *irq_self;

// forward refs
const mp_obj_type_t touch_class_type;

STATIC mp_obj_t modtouch_init_helper(modtouch_obj_t *self, size_t n_args,
                                        const mp_obj_t *pos_args, mp_map_t *kw_args);

// TSC_IRQHandler()
//
// This symbol is declared weak in startup_stm32.S and is put into the interrupt
// vector table there.
//
    void
TSC_IRQHandler(void)
{
    IRQ_ENTER(TSC_IRQn);

    //assert(irq_self);
    if(!irq_self) {
        // seems to happen during debug
        goto limp;
    }

    // Call HAL code, which will call either
    // HAL_TSC_ErrorCallback or HAL_TSC_ConvCpltCallback
    // ... always; no cases w/o that.
    HAL_TSC_IRQHandler(&irq_self->hw);

    if(irq_self->handler) {
        mp_sched_schedule(irq_self->handler, irq_self);
    }

    HAL_TSC_Stop_IT(&irq_self->hw);

    irq_self = NULL;

limp:
    IRQ_EXIT(TSC_IRQn);
}

// HAL_TSC_ConvCpltCallback()
//
    void
HAL_TSC_ConvCpltCallback(TSC_HandleTypeDef* htsc)
{
    // capture the results.
    irq_self->result1 = HAL_TSC_GroupGetValue(htsc, irq_self->group1);

    if(irq_self->group2 != -1) {
        irq_self->result2 = HAL_TSC_GroupGetValue(htsc, irq_self->group2);
    } else {
        irq_self->result2 = 0;
    }

}

// HAL_TSC_ErrorCallback()
//
    void
HAL_TSC_ErrorCallback(TSC_HandleTypeDef* htsc)
{
    // note the error
    irq_self->result1 = 0;
    irq_self->result2 = 0;
}


STATIC mp_obj_t modtouch_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *args) {

    // no args, except keywords
    mp_arg_check_num(n_args, n_kw, 0, 0, true);

    modtouch_obj_t *self = m_new_obj(modtouch_obj_t);
    memset(self, 0, sizeof(modtouch_obj_t));

    self->base.type = &touch_class_type;
    self->hw.Instance = TSC;
    self->initialized = false;
    self->group1 = self->group2 = -1;
    self->result1 = self->result2 = 0;

    if (n_kw > 0) {
        // configure and start it too
        mp_map_t kw_args;
        mp_map_init_fixed_table(&kw_args, n_kw, args + n_args);
        modtouch_init_helper(self, 0, 0, &kw_args);
    }

    return MP_OBJ_FROM_PTR(self);
}

STATIC void touch_print(const mp_print_t *print, mp_obj_t self_in, mp_print_kind_t kind) {
    modtouch_obj_t *self = self_in;

    if(!self->initialized) {
        mp_printf(print, "Touch(@%p)", self);

        return;
    }

    mp_printf(print, "Touch(@%p, ", self);

    TSC_InitTypeDef *init = &self->hw.Init;

    mp_printf(print, "channels=0x%08x, caps=0x%08x, ", init->ChannelIOs, init->ShieldIOs);
            
    mp_printf(print, "CTPH=%d, CTPL=%d, spread=%d, ", 
            ((init->CTPulseHighLength & TSC_CR_CTPH_Msk) >> TSC_CR_CTPH_Pos)+1,
            ((init->CTPulseLowLength & TSC_CR_CTPL_Msk) >> TSC_CR_CTPL_Pos)+1,
            (init->SpreadSpectrumDeviation & TSC_CR_SSD_Msk) >> TSC_CR_SSD_Pos
    );
    mp_printf(print, "pulse_prescale=%d, max_count=%d, ", 
            1<<((init->PulseGeneratorPrescaler&TSC_CR_PGPSC_Msk) >> TSC_CR_PGPSC_Pos),
            (256 << ((init->MaxCountValue & TSC_CR_MCV_Msk) >> TSC_CR_MCV_Pos))-1);

    mp_printf(print, "float_unused=%d, handler=%c", 
            (init->IODefaultMode == TSC_IODEF_IN_FLOAT),
            (self->handler ? 'Y' : 'N')
    );
    
#if 0
    if(irq_self) {
        mp_printf(print, ", busy=%s", (irq_self == self) ? "ME" : "other");
    }
#endif

    mp_printf(print, ")");
}

// remap_tsc_pin()
//
// Map port/pin to group+channel in TSC terms.
//
    STATIC int
remap_tsc_pin(const pin_obj_t *pin, GPIO_TypeDef **port)
{
#ifdef STM32L4
/*
    Table 1. IOs for the STM32L4xx devices
    +--------------------------------+
    |       IOs    |   TSC functions |
    |--------------|-----------------|
    |   PB12 (AF)  |   TSC_G1_IO1    |
    |   PB13 (AF)  |   TSC_G1_IO2    |
    |   PB14 (AF)  |   TSC_G1_IO3    |
    |   PB15 (AF)  |   TSC_G1_IO4    |
    |--------------|-----------------|
    |   PB4 (AF)   |   TSC_G2_IO1    |
    |   PB5 (AF)   |   TSC_G2_IO2    |
    |   PB6 (AF)   |   TSC_G2_IO3    |
    |   PB7 (AF)   |   TSC_G2_IO4    |
    |--------------|-----------------|
    |   PA15 (AF)  |   TSC_G3_IO1    |
    |   PC10 (AF)  |   TSC_G3_IO2    |
    |   PC11 (AF)  |   TSC_G3_IO3    |
    |   PC12 (AF)  |   TSC_G3_IO4    |
    |--------------|-----------------|
    |   PC6 (AF)   |   TSC_G4_IO1    |
    |   PC7 (AF)   |   TSC_G4_IO2    |
    |   PC8 (AF)   |   TSC_G4_IO3    |
    |   PC9 (AF)   |   TSC_G4_IO4    |
    |--------------|-----------------|
    |   PE10 (AF)  |   TSC_G5_IO1    |
    |   PE11 (AF)  |   TSC_G5_IO2    |
    |   PE12 (AF)  |   TSC_G5_IO3    |
    |   PE13 (AF)  |   TSC_G5_IO4    |
    |--------------|-----------------|
    |   PD10 (AF)  |   TSC_G6_IO1    |
    |   PD11 (AF)  |   TSC_G6_IO2    |
    |   PD12 (AF)  |   TSC_G6_IO3    |
    |   PD13 (AF)  |   TSC_G6_IO4    |
    |--------------|-----------------|
    |   PE2 (AF)   |   TSC_G7_IO1    |
    |   PE3 (AF)   |   TSC_G7_IO2    |
    |   PE4 (AF)   |   TSC_G7_IO3    |
    |   PE5 (AF)   |   TSC_G7_IO4    |
    |--------------|-----------------|
    |   PF14 (AF)  |   TSC_G8_IO1    |
    |   PF15 (AF)  |   TSC_G8_IO2    |
    |   PG0 (AF)   |   TSC_G8_IO3    |
    |   PG1 (AF)   |   TSC_G8_IO4    |
    |--------------|-----------------|
    |   PB10 (AF)  |   TSC_SYNC      |
    |   PD2 (AF)   |                 |
    +--------------------------------+
*/
    *port = NULL;

    switch(pin->port) {
        case 0:     // Port A: just one
            *port = GPIOA;
            if(pin->pin == 15) return TSC_GROUP3_IO1;
            return -1;

        case 1:     // Port B: PB1..
            *port = GPIOB;
            switch(pin->pin) {
                case 12: return TSC_GROUP1_IO1;
                case 13: return TSC_GROUP1_IO2;
                case 14: return TSC_GROUP1_IO3;
                case 15: return TSC_GROUP1_IO4;

                case 4:  return TSC_GROUP2_IO1;
                case 5:  return TSC_GROUP2_IO2;
                case 6:  return TSC_GROUP2_IO3;
                case 7:  return TSC_GROUP2_IO4;

                default: return -1;
            }
            break;

        case 2:     // Port C: PC1..
            *port = GPIOC;
            switch(pin->pin) {
                case 10: return TSC_GROUP3_IO2;
                case 11: return TSC_GROUP3_IO3;
                case 12: return TSC_GROUP3_IO4;

                case 6:  return TSC_GROUP4_IO1;
                case 7:  return TSC_GROUP4_IO2;
                case 8:  return TSC_GROUP4_IO3;
                case 9:  return TSC_GROUP4_IO4;

                default: return -1;
            }
            break;

        case 3:     // Port D: PD1..
            *port = GPIOD;
            switch(pin->pin) {
                case 10: return TSC_GROUP6_IO1;
                case 11: return TSC_GROUP6_IO2;
                case 12: return TSC_GROUP6_IO3;
                case 13: return TSC_GROUP6_IO4;

                default: return -1;
            }
            break;

        case 4:     // Port E: PE1..
            *port = GPIOE;
            switch(pin->pin) {
                case 10: return TSC_GROUP5_IO1;
                case 11: return TSC_GROUP5_IO2;
                case 12: return TSC_GROUP5_IO3;
                case 13: return TSC_GROUP5_IO4;

                case 2:  return TSC_GROUP7_IO1;
                case 3:  return TSC_GROUP7_IO2;
                case 4:  return TSC_GROUP7_IO3;
                case 5:  return TSC_GROUP7_IO4;

                default: return -1;
            }
            break;

        case 5:     // Port F: PF1..
            *port = GPIOF;
            switch(pin->pin) {
                case 14: return TSC_GROUP8_IO1;
                case 15: return TSC_GROUP8_IO2;

                default: return -1;
            }
            break;

        case 6:     // Port G: PG0..
            *port = GPIOG;
            switch(pin->pin) {
                case 0: return TSC_GROUP8_IO3;
                case 1: return TSC_GROUP8_IO4;

                default: return -1;
            }
            break;

        default: return -1;
    }
#else
#error "need a mapping here"
#endif
}

// tsc_group_for_pin()
//
    STATIC int
tsc_group_for_pin(uint32_t mask)
{
    for(int i=0; i<TSC_NB_OF_GROUPS; i++) {
        if((mask & ((uint32_t)0x0F << (i * 4)))) {
            return i;
        }
    }

    return -1;
}

// pin_list_to_mask()
//
    STATIC uint32_t
pin_list_to_mask(mp_obj_t *pin_list, bool claim, bool is_cap)
{
    uint32_t rv = 0;

    size_t len;
    mp_obj_t *array;
    mp_obj_get_array(pin_list, &len, &array);

    for(int i=0; i<len; i++) {
        const pin_obj_t *pin = pin_find(array[i]);
        if(!pin) {
            // error handle? Exception would have happened tho
            continue;
        }

        // remap to channel group / IO number for TSC
        GPIO_TypeDef *port = NULL;
        int mask = remap_tsc_pin(pin, &port);
        if(mask < 0) {
            nlr_raise(mp_obj_new_exception_msg_varg(&mp_type_ValueError,
                            "Pin(%q) not on TSC", pin->name));
        }
        rv |= mask;

/*
    we're supposed to do this:

    (#) GPIO pins configuration
      (++) Enable the clock for the TSC GPIOs using __HAL_RCC_GPIOx_CLK_ENABLE() macro.
      (++) Configure the TSC pins used as sampling IOs in alternate function output Open-Drain mode,
           and TSC pins used as channel/shield IOs in alternate function output Push-Pull mode
           using HAL_GPIO_Init() function.
*/

        if(claim) {
            // configure for our usage
            // Not clear if mp_hal_pin_config() can't do this stuff, so do ourselves.
            mp_hal_pin_config(pin, MP_HAL_PIN_MODE_ALT, 
                is_cap ? MP_HAL_PIN_MODE_OPEN_DRAIN : MP_HAL_PIN_MODE_OUTPUT,
                GPIO_AF9_TSC);

            // GPIO_MODE_AF_PP
            // GPIO_MODE_AF_OD
            GPIO_InitTypeDef cfg = {
                .Pin = (1 << pin->pin),
                .Mode = is_cap ? GPIO_MODE_AF_PP : GPIO_MODE_AF_OD,
                .Pull = GPIO_NOPULL,
                .Speed = GPIO_SPEED_FREQ_VERY_HIGH,     // ??
                .Alternate = GPIO_AF9_TSC
            };

            HAL_GPIO_Init(port, &cfg);
        }
    }

    return rv;
}

// Touch.init()
//
STATIC mp_obj_t modtouch_init_helper(modtouch_obj_t *self, size_t n_args, const mp_obj_t *pos_args, mp_map_t *kw_args) {
    TSC_InitTypeDef *init = &self->hw.Init;

    mp_arg_t allowed_args[] = {
        { MP_QSTR_channels, MP_ARG_REQUIRED|MP_ARG_OBJ },       // list of pins
        { MP_QSTR_caps, MP_ARG_REQUIRED|MP_ARG_OBJ },           // list of pins
        { MP_QSTR_CTPL, MP_ARG_INT, {.u_int = 1} },
        { MP_QSTR_CTPH, MP_ARG_INT, {.u_int = 1} },
        { MP_QSTR_spread, MP_ARG_INT, {.u_int = 127} },
        { MP_QSTR_pulse_prescale, MP_ARG_INT, {.u_int = 64} },
        { MP_QSTR_max_count, MP_ARG_INT, {.u_int = 8191} },
        { MP_QSTR_float_unused, MP_ARG_BOOL, {.u_bool = true} },
        { MP_QSTR_handler, MP_ARG_OBJ, {.u_obj = NULL} },
        { MP_QSTR_queue, MP_ARG_OBJ, {.u_obj = NULL} },     // unused, simulator compat
    };

    if(self->initialized && init->ChannelIOs) {
        // chan/caps args are optional if we've been here before
        allowed_args[0].flags &= ~MP_ARG_REQUIRED;
        allowed_args[1].flags &= ~MP_ARG_REQUIRED;
    }

    // parse args
    struct {
        // order must match allowed_args above
        mp_arg_val_t channels, caps, CTPL, CTPH, spread, pulse_prescale;
        mp_arg_val_t max_count, float_unused, handler, queue;
    } args;
    mp_arg_parse_all(n_args, pos_args, kw_args,
        MP_ARRAY_SIZE(allowed_args), allowed_args, (mp_arg_val_t*)&args);

    if(args.handler.u_obj) {
        if(!MP_OBJ_IS_FUN(args.handler.u_obj)) {
            mp_raise_TypeError("handler");
        }

        self->handler = args.handler.u_obj;
    } else {
        self->handler = NULL;
    }

    if(args.channels.u_obj) {
        // read list of pins.
        uint32_t channel_mask = pin_list_to_mask(args.channels.u_obj, true, false);
        uint32_t cap_mask = pin_list_to_mask(args.caps.u_obj, true, true);

        if((channel_mask & cap_mask) != 0) {
            mp_raise_ValueError("Same pin cannot be both channel and cap");
        }

        // set all configuration values
        // not really; we're not sampling yet
        init->ShieldIOs = 0;
        init->ChannelIOs = channel_mask;
        init->SamplingIOs = cap_mask;
    }

    if(    (args.CTPH.u_int < 1) || (args.CTPH.u_int > 16)
        || (args.CTPL.u_int < 1) || (args.CTPL.u_int > 16)
    ) {
        mp_raise_ValueError("CTPH & CTPL must be 1..16");
    }

    init->CTPulseHighLength = (args.CTPH.u_int-1) << TSC_CR_CTPH_Pos;
    init->CTPulseLowLength = (args.CTPL.u_int-1) << TSC_CR_CTPL_Pos;

    if(args.spread.u_int > 0) {
        init->SpreadSpectrum = TSC_CR_SSE;
        init->SpreadSpectrumDeviation = (args.spread.u_int << TSC_CR_SSD_Pos) & TSC_CR_SSD_Msk;
        init->SpreadSpectrumPrescaler = TSC_SS_PRESC_DIV1;
    } else {
        // disable spread-spectrum
        init->SpreadSpectrum = 0;
        init->SpreadSpectrumDeviation = 0;
        init->SpreadSpectrumPrescaler = 0;
    }

    switch(args.pulse_prescale.u_int) {
        case 1:  init->PulseGeneratorPrescaler = TSC_PG_PRESC_DIV1; break;
        case 2:  init->PulseGeneratorPrescaler = TSC_PG_PRESC_DIV2; break;
        case 4:  init->PulseGeneratorPrescaler = TSC_PG_PRESC_DIV4; break;
        case 8:  init->PulseGeneratorPrescaler = TSC_PG_PRESC_DIV8; break;
        case 16: init->PulseGeneratorPrescaler = TSC_PG_PRESC_DIV16; break;
        case 32: init->PulseGeneratorPrescaler = TSC_PG_PRESC_DIV32; break;
        case 64: init->PulseGeneratorPrescaler = TSC_PG_PRESC_DIV64; break;
        case 128:init->PulseGeneratorPrescaler = TSC_PG_PRESC_DIV128; break;
        default:
            mp_raise_ValueError("pulse_prescale");
    }

    switch(args.max_count.u_int) {
        case 255:   init->MaxCountValue = TSC_MCV_255; break;
        case 511:   init->MaxCountValue = TSC_MCV_511; break;
        case 1023:  init->MaxCountValue = TSC_MCV_1023; break;
        case 2047:  init->MaxCountValue = TSC_MCV_2047; break;
        case 8191:  init->MaxCountValue = TSC_MCV_8191; break;
        case 16383: init->MaxCountValue = TSC_MCV_16383; break;
        default:
            mp_raise_ValueError("max_count");
    }

    init->IODefaultMode = args.float_unused.u_bool ? TSC_IODEF_IN_FLOAT : TSC_IODEF_OUT_PP_LOW;

    // no support for sync mode here
    init->AcquisitionMode = TSC_ACQ_MODE_NORMAL;
    init->SynchroPinPolarity = TSC_SYNC_POLARITY_FALLING;

    init->MaxCountInterrupt = ENABLE;

    // enable clock to TSC
    __HAL_RCC_TSC_CLK_ENABLE();

    // no need for __HAL_RCC_GPIOA_CLK_ENABLE() .. etc, as done by mp_hal_pin_config()

    // call the real setup code.
    HAL_StatusTypeDef x = HAL_TSC_Init(&self->hw);
    if(x != HAL_OK) {
        mp_raise_ValueError("HAL_TSC_Init");
    }

    self->initialized = true;
    
    return mp_const_none;
}


STATIC mp_obj_t modtouch_init(size_t n_args, const mp_obj_t *args, mp_map_t *kw_args) {
    return modtouch_init_helper(args[0], n_args - 1, args + 1, kw_args);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_KW(modtouch_init_obj, 1, modtouch_init);



STATIC mp_obj_t modtouch_discharge(mp_obj_t self_in) {
    modtouch_obj_t *self = self_in;

    HAL_StatusTypeDef x = HAL_TSC_IODischarge(&self->hw, ENABLE);
    if(x != HAL_OK) {
        mp_raise_ValueError("HAL_TSC_IODischarge");
    }

    return mp_const_none;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(modtouch_discharge_obj, modtouch_discharge);


// sample SINGLE pin
//
// - takes about 12ms to complete (with default settings)
// - timeout based on max_count value
// - requires caller to do discharge step and 1ms delay
//
STATIC mp_obj_t modtouch_sample(mp_obj_t self_in, mp_obj_t which_pin)
{
    modtouch_obj_t *self = self_in;
    HAL_StatusTypeDef x;

    const pin_obj_t *pin = pin_find(which_pin);
    GPIO_TypeDef *port = NULL;
    uint32_t mask = remap_tsc_pin(pin, &port);
    int group = tsc_group_for_pin(mask);

    if((mask & self->hw.Init.ChannelIOs) == 0) {
        mp_raise_ValueError("not setup to sample that pin");
    }

    assert(group >= 0);
    assert(group < 8);

    // configure to sample specific pin
    TSC_IOConfigTypeDef config = {
        //.ChannelIOs = self->hw.Init.ChannelIOs,
        .ChannelIOs = mask,
        .ShieldIOs = self->hw.Init.ShieldIOs,
        .SamplingIOs = self->hw.Init.SamplingIOs,
    };

    x = HAL_TSC_IOConfig(&self->hw, &config);
    if(x != HAL_OK) {
        mp_raise_ValueError("HAL_TSC_IOConfig");
    }

    // NOTE: discharge must be done before we are called
#if 0
    HAL_TSC_IODischarge(&self->hw, ENABLE);
    mp_hal_delay_ms(1);
#endif

    x = HAL_TSC_Start(&self->hw);
    if(x != HAL_OK) {
        mp_raise_ValueError("HAL_TSC_Start");
    }

    while(HAL_TSC_GetState(&self->hw) == HAL_TSC_STATE_BUSY) {
        // busy wait
    }
    x = HAL_TSC_GetState(&self->hw);
    uint32_t count = 0;
    switch(x) {
        case HAL_TSC_STATE_READY: 
            count = HAL_TSC_GroupGetValue(&self->hw, group);
            break;
        case HAL_TSC_STATE_ERROR: 
            // acquisition is completed with max count error
            count = 0;
            break;
        default:
            mp_raise_ValueError("TSC State");
            break;
    }

    HAL_TSC_Stop(&self->hw);

    return MP_OBJ_NEW_SMALL_INT(count);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_2(modtouch_sample_obj, modtouch_sample);


// sample TWO pins at same time
//
// unused?
//
STATIC mp_obj_t modtouch_sample_two(mp_obj_t self_in, mp_obj_t pin1_in, mp_obj_t pin2_in)
{
    modtouch_obj_t *self = self_in;
    HAL_StatusTypeDef x;

    GPIO_TypeDef *port = NULL;
    uint32_t mask = remap_tsc_pin(pin_find(pin1_in), &port);
    int group1 = tsc_group_for_pin(mask);

    uint32_t mask2 = remap_tsc_pin(pin_find(pin2_in), &port);
    int group2 = tsc_group_for_pin(mask2);

    if(group1 == group2) {
        mp_raise_ValueError("pins must be in different groups");
    }

    mask |= mask2;

    if((mask & self->hw.Init.ChannelIOs) == 0) {
        mp_raise_ValueError("not setup to sample that pin");
    }


    // configure to sample specific pin
    TSC_IOConfigTypeDef config = {
        .ChannelIOs = mask,
        .ShieldIOs = self->hw.Init.ShieldIOs,
        .SamplingIOs = self->hw.Init.SamplingIOs,
    };

    x = HAL_TSC_IOConfig(&self->hw, &config);
    if(x != HAL_OK) {
        mp_raise_ValueError("HAL_TSC_IOConfig");
    }

    // NOTE: discharge must be done before we are called

    x = HAL_TSC_Start(&self->hw);
    if(x != HAL_OK) {
        mp_raise_ValueError("HAL_TSC_Start");
    }

    while(HAL_TSC_GetState(&self->hw) == HAL_TSC_STATE_BUSY) {
        // busy wait
    }
    x = HAL_TSC_GetState(&self->hw);
    uint32_t count1 = 0, count2 = 0;
    switch(x) {
        case HAL_TSC_STATE_READY: 
            count1 = HAL_TSC_GroupGetValue(&self->hw, group1);
            count2 = HAL_TSC_GroupGetValue(&self->hw, group2);
            break;
        case HAL_TSC_STATE_ERROR: 
            // acquisition is completed with max count error; return zeros
            break;
        default:
            mp_raise_ValueError("TSC State");
            break;
    }

    HAL_TSC_Stop(&self->hw);

    mp_obj_t tuple[2] = {
        MP_OBJ_NEW_SMALL_INT(count1),
        MP_OBJ_NEW_SMALL_INT(count2),
    };
    return mp_obj_new_tuple(2, tuple);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_3(modtouch_sample_two_obj, modtouch_sample_two);


// Interrupt-based touch sampling of upto TWO pins at same time
//
STATIC mp_obj_t modtouch_start_sample(size_t n_args, const mp_obj_t *args)
{
    modtouch_obj_t *self = args[0];
    HAL_StatusTypeDef x;

    GPIO_TypeDef *port = NULL;
    uint32_t mask = remap_tsc_pin(pin_find(args[1]), &port);
    self->group1 = tsc_group_for_pin(mask);

    if(n_args >= 3) {
        const pin_obj_t *pin2 = pin_find(args[2]);
        uint32_t mask2 = remap_tsc_pin(pin2, &port);
        self->group2 = tsc_group_for_pin(mask2);

        if(self->group1 == self->group2) {
            mp_raise_ValueError("pins must be in different groups");
        }

        mask |= mask2;
    } else {
        self->group2 = -1;
    }

    if((mask & self->hw.Init.ChannelIOs) == 0) {
        mp_raise_ValueError("not setup to sample that pin");
    }

    // Commit to being the handler. Be sure to clear
    // any error cases, before getting to this point.
    // This is atomic test and set.
    if(!__sync_bool_compare_and_swap(&irq_self, NULL, self)) {
        // this used to raise but since usually caused by
        // a race, it's better to return
        return mp_const_true;
    }

    // configure to sample specific pin now
    TSC_IOConfigTypeDef config = {
        .ChannelIOs = mask,
        .ShieldIOs = self->hw.Init.ShieldIOs,
        .SamplingIOs = self->hw.Init.SamplingIOs,
    };

    x = HAL_TSC_IOConfig(&self->hw, &config);
    if(x != HAL_OK) {
        irq_self = NULL;
        mp_raise_ValueError("HAL_TSC_IOConfig");
    }

    HAL_NVIC_SetPriority(TSC_IRQn, IRQ_PRI_CAN, 0);
    HAL_NVIC_EnableIRQ(TSC_IRQn);

    x = HAL_TSC_Start_IT(&self->hw);
    if(x != HAL_OK) {
        irq_self = NULL;
        mp_raise_ValueError("HAL_TSC_Start_IT");
    }

    return mp_const_none;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(modtouch_start_sample_obj, 2, 3, modtouch_start_sample);


// readback results from interrupt handler, or
// - None if not finished yet
// - (a,b) if dual sample
// - N if single sample
//
STATIC mp_obj_t modtouch_finished(mp_obj_t self_in)
{
    modtouch_obj_t *self = self_in;

    if(irq_self) {
        // not done interrupt handling yet
        return mp_const_none;
    }

    if(self->group2 == -1) {
        return MP_OBJ_NEW_SMALL_INT(self->result1);
    } else {
        mp_obj_t tuple[2] = {
            MP_OBJ_NEW_SMALL_INT(self->result1),
            MP_OBJ_NEW_SMALL_INT(self->result2),
        };

        return mp_obj_new_tuple(2, tuple);
    }
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(modtouch_finished_obj, modtouch_finished);



STATIC mp_obj_t pins_to_mask_helper(mp_obj_t pin_list)
{
    uint32_t mask = pin_list_to_mask(pin_list, false, false);

    return MP_OBJ_NEW_SMALL_INT(mask);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(pins_to_mask_obj, pins_to_mask_helper);



STATIC mp_obj_t pin_to_group_helper(mp_obj_t pin_name)
{
    const pin_obj_t *pin = pin_find(pin_name);
    GPIO_TypeDef *port = NULL;
    uint32_t mask = remap_tsc_pin(pin, &port);
    int group = tsc_group_for_pin(mask);

    return MP_OBJ_NEW_SMALL_INT(group);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(pin_to_group_obj, pin_to_group_helper);


STATIC const mp_rom_map_elem_t modtouch_locals_dict_table[] = {
    // instance methods

    { MP_ROM_QSTR(MP_QSTR_init), MP_ROM_PTR(&modtouch_init_obj) },
    { MP_ROM_QSTR(MP_QSTR_discharge), MP_ROM_PTR(&modtouch_discharge_obj) },
    { MP_ROM_QSTR(MP_QSTR_sample), MP_ROM_PTR(&modtouch_sample_obj) },
    { MP_ROM_QSTR(MP_QSTR_sample_two), MP_ROM_PTR(&modtouch_sample_two_obj) },
    { MP_ROM_QSTR(MP_QSTR_start_sample), MP_ROM_PTR(&modtouch_start_sample_obj) },
    { MP_ROM_QSTR(MP_QSTR_finished), MP_ROM_PTR(&modtouch_finished_obj) },
    //{ MP_ROM_QSTR(MP_QSTR_deinit), MP_ROM_PTR(&modtouch_deinit_obj) },

};
STATIC MP_DEFINE_CONST_DICT(modtouch_locals_dict, modtouch_locals_dict_table);


const mp_obj_type_t touch_class_type = {
    { &mp_type_type },
    .name = MP_QSTR_Touch,
    .make_new = modtouch_make_new,
    .print = touch_print,
    //.protocol = &mp_machine_soft_i2c_p,
    .locals_dict = (mp_obj_dict_t*)&modtouch_locals_dict,
};


STATIC const mp_rom_map_elem_t touch_module_globals_table[] = {
    { MP_ROM_QSTR(MP_QSTR___name__),        MP_ROM_QSTR(MP_QSTR_touch) },
    { MP_ROM_QSTR(MP_QSTR_Touch),           MP_ROM_PTR(&touch_class_type) },
    { MP_ROM_QSTR(MP_QSTR_pins_to_mask),    MP_ROM_PTR(&pins_to_mask_obj) },
    { MP_ROM_QSTR(MP_QSTR_pin_to_group),    MP_ROM_PTR(&pin_to_group_obj) },
};

STATIC MP_DEFINE_CONST_DICT(touch_module_globals, touch_module_globals_table);

const mp_obj_module_t touch_module = {
    .base = { &mp_type_module },
    .globals = (mp_obj_dict_t*)&touch_module_globals,
};
