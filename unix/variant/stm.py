# STM

class MockMemory:
    def __init__(self, mapping, default):
        self.mapping = mapping
        self.default = default

    def __index__(self, offset):
        return self.mapping.get(offset, self.default)

mem32 = MockMemory({}, 0)
mem8 = MockMemory({}, 0)
