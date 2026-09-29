# Fish completion for apt.

function __fish_apt_complete
    set -l commands (command apt __complete 2>/dev/null)
    set -l command
    set -l current (commandline -ct)

    for word in (commandline -opc)
        if contains -- $word $commands
            set command $word
            break
        end
    end

    if test -n "$command"
        if string match -qr '^-' -- $current
            command apt __complete $command 2>/dev/null
        end
    else if string match -qr '^-' -- $current
        command apt __complete '' 2>/dev/null
    else
        printf '%s\n' $commands
    end
end

complete -c apt -f -a '(__fish_apt_complete)'
