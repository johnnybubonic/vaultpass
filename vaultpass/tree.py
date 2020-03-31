# Thanks, dude: https://stackoverflow.com/a/49912639/733214
# TODO?


class Tree(object):
    prefix_middle = '├──'
    prefix_last = '└──'
    spacer_middle = (' ' * 4)
    spacer_last = ('│' + (' ' * 3))
    parent_fmt = '\033[01;34m{0}/\033[00m'
    depth = 0

