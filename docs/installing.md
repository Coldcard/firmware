
# Check-out and build

- clone repo
- do submodule magic in `external`
- make top-level virtual env: `virtualenv -p python3 ENV`
- activate it
- then:

    cd external/ckcc-protocol
    pip install -r requirements.txt
    pip install --editable .
    cd ../..
    pip install -r requirements.txt
    pip install -r unix/requirements.txt

- should give you a command-line program "ckcc" in your path
- should be able to do:

    cd unix
    make && ./simulator.py


