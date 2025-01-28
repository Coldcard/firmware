#
# (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#

font_files = {
    'small': 'assets/zevv-peep-iso8859-15-07x14.bdf',
    'large': 'assets/zevv-peep-iso8859-15-10x20.bdf',
    'tiny': 'assets/4x6.bdf',
}

# test with:
#   ./build.py build --portable && ./testit.py --msg "hello→world←\n↳this\n•Bullet\n•Text" -f small
#
special_chars = dict(small=[
('→', dict(y=0), '''\



          
          x
          xx
  xxxxxxxxxxx 
          xx
          x
'''),
('←', dict(y=0), '''\



          
    x      
   xx       
  xxxxxxxxxxx 
   xx       
    x      
'''),
('↳', dict(y=0), '''\

   x 
   x 
   x      
   x      x
   x      xx
   xxxxxxxxxx 
          xx
          x
'''),
('•', dict(y=0), '''\





      xxx  
      xxx 
      xxx 
'''),
('-', dict(y=0), '''\






  xxxxx 
'''),
('⋯', dict(y=0), '''\






  x x x x x
'''),

# thin space
('\u2009', dict(y=0, w=5), '''\

'''),

])
