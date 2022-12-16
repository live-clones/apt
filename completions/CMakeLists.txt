set(BASH_COMPLETION_DIR "${CMAKE_INSTALL_DATAROOTDIR}/bash-completion/completions"
    CACHE PATH "Path to the bash-completion completions directory")

install(FILES bash/apt DESTINATION ${BASH_COMPLETION_DIR})
install(FILES bash/apt-cache DESTINATION ${BASH_COMPLETION_DIR})
install(FILES bash/apt-get DESTINATION ${BASH_COMPLETION_DIR})
