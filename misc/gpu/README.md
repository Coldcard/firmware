
# GPU on Q1

The name is a joke. It's not a GPU, just a very simple and cheap micro that can
animate a progress bar. And that's all we want it to do.

It is field upgradable, but we may remove that and start locking it down in 
production once it's features are stable.


## Hardware

It's a STM32C011F4:

- 16k bytes of Flash
- 6k bytes of RAM
- 4-48Mhz
- 18 GPIO
- 20 pins

Of the two TagConnect spots, the GPU is the inboard one; other is for main micro.

## Notes

- AN4221 describes the protocol used to load the flash
- timing is sensitive, but more important is where the i2c start/stops fall:

```python
>>> from machine import I2C, Pin
>>> i2c = I2C(1, freq=400000)

>>> r = Pin('G_RESET')
>>> r
Pin(Pin.cpu.E6, mode=Pin.OUT)
>>> r.init(mode=Pin.OPEN_DRAIN, pull=Pin.PULL_UP)
>>> r()
0
>>> r(1)
>>> r()
1
>>> [hex(i) for i in i2c.scan()]
['0x2d', '0x51', '0x53', '0x55', '0x57', '0x64']

# for SWI to work, also:
>>> gg=Pin('G_SWCLK_B0')
>>> gg.init(mode=Pin.IN)


# Get - reveals bootloader version, commands (v1.2)
>>> i2c.writeto(0x64, b'\x00\xff'); i2c.readfrom(0x64, 1); i2c.readfrom(0x64, 20); i2c.readfrom(0x64, 1);
2
b'y'
b'\x12\x11\x00\x01\x02\x11!1Dcs\x82\x922Edt\x83\x93\xa1'
b'y'

# Get ID command
>>> i2c.writeto(0x64, b'\x02\xfd'); i2c.readfrom(0x64, 1); [hex(i) for i in i2c.readfrom(0x64, 3)]; i2c.readfrom(2x64, 1);
b'y'
['0x1', '0x4', '0x43']
b'y'


```
