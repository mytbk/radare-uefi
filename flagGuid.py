def flagGuid(r, s, g):
    print("flagging {}".format(s))
    sr = r.cmdj("/xj {}".format(g));
    for x in sr:
        r.cmd("f {} @ {}".format(s, x["offset"]))
