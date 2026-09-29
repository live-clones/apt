set(BASH_COMPLETION_DIR "${CMAKE_INSTALL_DATAROOTDIR}/bash-completion/completions"
    CACHE PATH "Path to the bash-completion completions directory")
set(FISH_COMPLETION_DIR "${CMAKE_INSTALL_DATAROOTDIR}/fish/vendor_completions.d"
    CACHE PATH "Path to the fish-completion completions directory")

install(FILES bash/apt DESTINATION ${BASH_COMPLETION_DIR})
install(FILES fish/apt.fis:set fixeol
h DESTINATION ${FISH_COMPLETION_DIR})
