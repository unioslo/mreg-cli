from cli import cli, Flag

####################################
#  Add the main command 'history'  #
####################################

history = cli.add_command(
    prog='history',
    description='Undo, redo or print history for this program session.',
)


#########################################
# Implementation of sub command 'print' #
#########################################

def print_(args):
    print('pringing history.')


history.add_command(
    prog='print',
    description='Print the history',
    short_desc='Print the history',
    callback=print_,
)

########################################
# Implementation of sub command 'redo' #
########################################

def redo(args):
    print('redo:', args.num)


history.add_command(
    prog='redo',
    description='Redo some history event given by NUM (GET '
                'requests are not redone)',
    short_desc='Redo history.',
    callback=redo,
    flags=[
        Flag('num',
             description='History number of the event to redo.',
             metavar='NUM'),
    ]
)


########################################
# Implementation of sub command 'undo' #
########################################

def undo(args):
    print('undo:', args.num)


history.add_command(
    prog='undo',
    description='Undo some history event given by <history-number> (GET '
                'requests are not redone)',
    short_desc='Undo history.',
    callback=undo,
    flags=[
        Flag('num',
             description='History number of the event to undo.',
             metavar='NUM'),
    ]
)
