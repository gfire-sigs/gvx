
# gvx overrides, appended to tests/misc.sh by build-bundle.sh. They replace
# pipelines of tail, egrep, and dd with shell builtins, because each process
# start in the guest costs more than on a host. expect prints a TAP line for
# each check.

_nl='
'
expect()
{
	e="${1}"
	shift
	r=$(${fstest} $* 2>/dev/null)
	r=${r##*$_nl}
	_m=1
	case "${e}" in
	*'('*|*'*'*|*'['*|*'.'*|*'+'*|*'?'*|*'^'*|*'$'*)
		echo "${r}" | ${GREP} -Eq '^'${e}'$' && _m=0
		;;
	*)
		case "|${e}|" in
		*"|${r}|"*) _m=0 ;;
		esac
		;;
	esac
	if [ $_m -eq 0 ]; then
		if [ -z "${todomsg}" ]; then
			echo "ok ${ntest}"
		else
			echo "ok ${ntest} # TODO ${todomsg}"
		fi
	else
		if [ -z "${todomsg}" ]; then
			echo "not ok ${ntest} - tried '$*', expected ${e}, got ${r}"
		else
			echo "not ok ${ntest} # TODO ${todomsg}"
		fi
	fi
	todomsg=""
	: $(( ntest += 1 ))
}

namegen()
{
	read _u < /proc/sys/kernel/random/uuid
	while [ "${_u#*-}" != "$_u" ]; do _u="${_u%%-*}${_u#*-}"; done
	echo "pjdfstest_${_u}"
}

namegen_len()
{
	len="${1}"
	name=""
	while [ ${#name} -lt ${len} ]; do
		read _u < /proc/sys/kernel/random/uuid
		while [ "${_u#*-}" != "$_u" ]; do _u="${_u%%-*}${_u#*-}"; done
		name="${name}${_u}"
	done
	while [ ${#name} -gt ${len} ]; do
		name="${name%?}"
	done
	printf "%s" "${name}"
}
