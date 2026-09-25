libusermode_linux_h = include_directories(
    '..', '../..'
)
libusermode_linux = static_library('usermode_linux',
    'dl_rendezvous.cpp',
    'utils.cpp',

    dependencies : deps,
    include_directories : libusermode_linux_h,
    link_with : [libdrakvuf, libusermode]
)

if check.found()
    libusermode_linux_check = executable('libusermode_linux_check',
        sources : 'check.cpp',
        include_directories : libusermode_linux_h,
        dependencies : [deps, check],
        link_with : [libdrakvuf, libusermode, libusermode_linux],
        install : false
    )
    test('libusermode_linux_check', libusermode_linux_check)
endif
