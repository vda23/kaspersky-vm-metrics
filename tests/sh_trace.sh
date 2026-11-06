# shellcheck shell=bash
# Подключается через BASH_ENV в тестах установщика (покрытие функций install.sh).
# Каждая выполненная команда пишется в $KVM_SH_TRACE как «+<функция>|<команда>».
if [ -n "${KVM_SH_TRACE:-}" ]; then
    exec 9>>"$KVM_SH_TRACE"
    BASH_XTRACEFD=9
    PS4='+${FUNCNAME[0]:-main}|'
    set -x
fi
