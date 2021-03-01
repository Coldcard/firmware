//
// module top-level
//
#include "py/obj.h"
#include "py/runtime.h"
#include "py/builtin.h"
#include "aes_256_ctr.h"

#if MICROPY_ENABLE_DYNRUNTIME
#error "Static Only"
#endif

// AES block size
#define BLKSIZE 16

typedef struct  {
    mp_obj_base_t   base;
    uint8_t         runt[BLKSIZE];
    int             runt_len;
    param           p;
} mp_obj_AES256CTR_t;

STATIC const mp_obj_type_t s_AES256CTR_type;

STATIC mp_obj_t s_AES256CTR_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *args) {
    // args: key, nonce
    mp_arg_check_num(n_args, n_kw, 1, 2, false);

    mp_buffer_info_t key;
    mp_get_buffer_raise(args[0], &key, MP_BUFFER_READ);

    if(key.len != 32) {
        // only AES-256 here
        mp_raise_ValueError(NULL);
    }

    mp_obj_AES256CTR_t *o = m_new_obj_with_finaliser(mp_obj_AES256CTR_t);
    o->base.type = type;

    // state setup, and key schedule
    memset(&o->p, 0, sizeof(param));
    o->runt_len = 0;

    if(n_args == 2) {
        mp_buffer_info_t n_in;
        mp_get_buffer_raise(args[1], &n_in, MP_BUFFER_READ);
        if(n_in.len > 16) {
            mp_raise_ValueError(NULL);
        }
        // can be 12 bytes of nonce + 4 bytes ctr, or just all 16 bytes of state
        memcpy(o->p.nonce, n_in.buf, n_in.len);
    }

    // key setup
    memcpy(o->p.rk, key.buf, 32);
    AES_256_keyschedule(key.buf, o->p.rk+32);
    
    return o;
}

    static bool inline
is_unaligned(const void *p)
{
    return !!(((uint32_t)p) & 0x3);
}

STATIC mp_obj_t s_AES256CTR_cipher(mp_obj_t self_in, mp_obj_t buf_in)
{
    mp_obj_AES256CTR_t *self = MP_OBJ_TO_PTR(self_in);

    mp_buffer_info_t buf;
    mp_get_buffer_raise(buf_in, &buf, MP_BUFFER_READ);

    int len = buf.len, in_len = buf.len;
    const uint8_t *inp = buf.buf;
    uint8_t *rv = m_malloc(in_len);
    uint8_t *outp = rv;

    if(self->runt_len) {
        // we've already encrypted (w/ zero bytes) for this part
        uint8_t *ch = &self->runt[BLKSIZE - self->runt_len];
        while(self->runt_len && in_len) {
            *(outp++) = *(inp++) ^ *(ch++);
            self->runt_len --;
            in_len --;
        }
    }

    bool nogood = (is_unaligned(inp) || is_unaligned(outp));

    while(in_len) {
        if(in_len >= BLKSIZE) {
            if(nogood) {
                uint8_t     blk[BLKSIZE];

                // align data so ASM can work
                memcpy(blk, inp, BLKSIZE);
                AES_256_encrypt_ctr(&self->p, blk, blk, BLKSIZE);
                memcpy(outp, blk, BLKSIZE);
            } else {
                // rare? but faster case
                AES_256_encrypt_ctr(&self->p, inp, outp, BLKSIZE);
            }

            outp += BLKSIZE;
            inp += BLKSIZE;
            in_len -= BLKSIZE;
        } else {
            uint8_t     blk[BLKSIZE] = {};
            memcpy(blk, inp, in_len);

            AES_256_encrypt_ctr(&self->p, blk, self->runt, BLKSIZE);
            memcpy(outp, self->runt, in_len);
            self->runt_len = BLKSIZE - in_len;
            in_len = 0;
        }
        
        // inc counter (big endian, assumes nonce != ~0)
        uint8_t *ctr = &self->p.ctr[3];
        while(1) {
            ctr[0] += 1;
            if(ctr[0]) break;
            ctr--;
        }
    }

    return mp_obj_new_bytearray_by_ref(len, rv);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_2(s_AES256CTR_cipher_obj, s_AES256CTR_cipher);

STATIC mp_obj_t s_AES256CTR_copy(mp_obj_t self_in) {
    mp_obj_AES256CTR_t *self = MP_OBJ_TO_PTR(self_in);

    mp_obj_AES256CTR_t *rv = m_new_obj_with_finaliser(mp_obj_AES256CTR_t);
    *rv = *self;
    rv->base.type = &s_AES256CTR_type;
    
    return rv;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(s_AES256CTR_copy_obj, s_AES256CTR_copy);


STATIC mp_obj_t s_AES256CTR_blank(mp_obj_t self_in) {
    mp_obj_AES256CTR_t *self = MP_OBJ_TO_PTR(self_in);

    // cf_aes_finish is just this anyway
    memset(self, 0, sizeof(mp_obj_AES256CTR_t));
    self->base.type = &s_AES256CTR_type;
    
    return self_in;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(s_AES256CTR_blank_obj, s_AES256CTR_blank);


STATIC const mp_rom_map_elem_t s_AES256CTR_locals_dict_table[] = {
    { MP_ROM_QSTR(MP_QSTR_cipher), MP_ROM_PTR(&s_AES256CTR_cipher_obj) },
    { MP_ROM_QSTR(MP_QSTR_blank), MP_ROM_PTR(&s_AES256CTR_blank_obj) },
    { MP_ROM_QSTR(MP_QSTR_blank), MP_ROM_PTR(&s_AES256CTR_blank_obj) },
    { MP_ROM_QSTR(MP_QSTR_copy), MP_ROM_PTR(&s_AES256CTR_copy_obj) },
    { MP_ROM_QSTR(MP_QSTR___del__), MP_ROM_PTR(&s_AES256CTR_blank_obj) },
};
STATIC MP_DEFINE_CONST_DICT(s_AES256CTR_locals_dict, s_AES256CTR_locals_dict_table);

STATIC const mp_obj_type_t s_AES256CTR_type = {
    { &mp_type_type },
    .name = MP_QSTR_AES256CTR,
    .make_new = s_AES256CTR_make_new,
    .locals_dict = (void *)&s_AES256CTR_locals_dict,
};


STATIC const mp_rom_map_elem_t mp_module_aes256ctr_globals_table[] = {
    { MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_aes256ctr) },

    { MP_ROM_QSTR(MP_QSTR_new), MP_ROM_PTR(&s_AES256CTR_type) },
};

STATIC MP_DEFINE_CONST_DICT(mp_module_aes256ctr_globals, mp_module_aes256ctr_globals_table);

const mp_obj_module_t mp_module_aes256ctr = {
    .base = { &mp_type_module },
    .globals = (mp_obj_dict_t *)&mp_module_aes256ctr_globals,
};

MP_REGISTER_MODULE(MP_QSTR_aes256ctr, mp_module_aes256ctr, 1);


