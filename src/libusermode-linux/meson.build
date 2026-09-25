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
