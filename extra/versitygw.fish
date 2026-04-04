# Fish completion for versitygw
function __versitygw_complete
    set -l cmd (commandline -opc)
    eval $cmd --generate-bash-completion
end
complete -f -c versitygw -a '(__versitygw_complete)'
