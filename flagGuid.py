def flagGuid(r, s, g):
    sr = r.cmdj("/xj {}".format(g));
    for x in sr:
        r.cmd("f {} @ {}".format(s, x["offset"]))
