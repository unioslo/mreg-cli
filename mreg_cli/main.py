if __name__ == '__main__':

    # Will ask for password
    import util
    util.update_token()
    print(util.session.headers["Authorization"])


    # shlex is a lexical analyser which handles quotes automatically, and
    # will allow handling of comments in input if necessary
    import shlex

    from prompt_toolkit import HTML
    from prompt_toolkit.shortcuts import CompleteStyle, PromptSession

    from cli import cli

    # Must import the commands, for the side effects of creating the commands
    # when importing.
    import dhcp
    import host
    import network
    import zone
    import history

    # session is a PromptSession object from prompt_toolkit which handles
    # some configurations of the prompt for us: the text of the prompt; the
    # completer; and other visual things.
    session = PromptSession(message=HTML('<b>mreg</b>> '),
                            search_ignore_case=True,
                            completer=cli,
                            complete_while_typing=True,
                            complete_style=CompleteStyle.MULTI_COLUMN)

    # Welcome text for the app
    print('Type -h for help.')

    # The app runs in an infinite loop and is expected to exit using sys.exit()
    while True:
        line = session.prompt()
        cli.parse(shlex.split(line))
