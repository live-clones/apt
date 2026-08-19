set(BASH_COMPLETION_DIR "${CMAKE_INSTALL_DATAROOTDIR}/bash-completion/completions"
    CACHE PATH "Path to the bash-completion completions directory")
set(ZSH_COMPLETION_DIR "${CMAKE_INSTALL_DATAROOTDIR}/zsh/vendor-completions"
    CACHE PATH "Path to the zsh-completion completions directory")

install(FILES bash/apt DESTINATION ${BASH_COMPLETION_DIR})
install(FILES zsh/_apt DESTINATION ${ZSH_COMPLETION_DIR})
