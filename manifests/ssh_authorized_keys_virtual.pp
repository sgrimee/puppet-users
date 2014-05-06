define users::ssh_authorized_keys_virtual (
    $user,
    $hash,
    $tag = undef,
) {
 
	@ssh_authorized_key { "${user}-${name}" :
	    ensure   => $hash[$name]['ensure'],
	    key      => $hash[$name]['key'],
	    options  => $hash[$name]['options'],
	    provider => $hash[$name]['provider'],
	    target   => $hash[$name]['target'],
	    type     => $hash[$name]['type'],
	    user     => $user,
            tag      => $tag,
	}

}
