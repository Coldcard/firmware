import sim_display

if sim_display.story:
    RV.write('\0'.join(sim_display.story))
    sim_display.story = None
else:
    RV.write('\0')

