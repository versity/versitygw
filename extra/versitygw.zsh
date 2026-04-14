#compdef versitygw
_versitygw() {
    local -a opts
    local cur
    cur=${words[-1]}
    if [[ "$cur" == "-"* ]]; then
        opts=("${(@f)$(${words[1,-2]} ${cur} --generate-bash-completion)}")
    else
        opts=("${(@f)$(${words[1,-2]} --generate-bash-completion)}")
    fi
    _describe 'versitygw' opts
}
_versitygw
