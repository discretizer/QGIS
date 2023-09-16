set(AUTH_AWSSSO_SRCS
  core/qgsauthawsssomethod.cpp
)

set(AUTH_AWSSSO_HDRS
  core/qgsauthawsssomethod.h
)

set(AUTH_AWSSSO_UIS_H "")

if (WITH_GUI)
  set(AUTH_AWSSSO_SRCS ${AUTH_AWSSSO_SRCS}
    gui/qgsauthawsssoedit.cpp
  )
  set(AUTH_AWSSSO_HDRS ${AUTH_AWSSSO_HDRS}
    gui/qgsauthawsssoedit.h
  )
  set(AUTH_AWSSSO_UIS gui/qgsauthawsssoedit.ui)
  if (BUILD_WITH_QT6)
    QT6_WRAP_UI(AUTH_AWSSSO_UIS_H ${AUTH_AWSSSO_UIS})
  else()
    QT5_WRAP_UI(AUTH_AWSSSO_UIS_H ${AUTH_AWSSSO_UIS})
  endif()
endif()


# static library
add_library(authmethod_awssso_a STATIC ${AUTH_AWSSSO_SRCS} ${AUTH_AWSSSO_HDRS} ${AUTH_AWSSSO_UIS_H})

target_include_directories(authmethod_awssso_a PUBLIC ${CMAKE_SOURCE_DIR}/src/auth/awssso/core)

# require c++17
target_compile_features(authmethod_awssso_a PRIVATE cxx_std_17)

target_link_libraries(authmethod_awssso_a qgis_core)

if (WITH_GUI)
  target_include_directories(authmethod_awssso_a PRIVATE
    ${CMAKE_SOURCE_DIR}/src/auth/awssso/gui
    ${CMAKE_BINARY_DIR}/src/auth/awssso
  )

  target_link_libraries (authmethod_awssso_a qgis_gui)
endif()

target_compile_definitions(authmethod_awssso_a PRIVATE "-DQT_NO_FOREACH")



if (FORCE_STATIC_LIBS)
  # for (external) mobile apps to be able to pick up provider for linking
  install (TARGETS authmethod_awssso_a ARCHIVE DESTINATION ${QGIS_PLUGIN_DIR})
else()
  # dynamically loaded module
  add_library(authmethod_awssso MODULE ${AUTH_AWSSSO_SRCS} ${AUTH_AWSSSO_HDRS} ${AUTH_AWSSSO_UIS_H})

  # require c++17
  target_compile_features(authmethod_awssso PRIVATE cxx_std_17)

  target_link_libraries(authmethod_awssso qgis_core)

  if (WITH_GUI)
    target_include_directories(authmethod_awssso PRIVATE
      ${CMAKE_SOURCE_DIR}/src/auth/awssso/gui
      ${CMAKE_BINARY_DIR}/src/auth/awssso
    )
    target_link_libraries (authmethod_awssso qgis_gui)
    add_dependencies(authmethod_awssso ui)
  endif()

  target_compile_definitions(authmethod_awssso PRIVATE "-DQT_NO_FOREACH")

  install (TARGETS authmethod_awssso
    RUNTIME DESTINATION ${QGIS_PLUGIN_DIR}
    LIBRARY DESTINATION ${QGIS_PLUGIN_DIR}
  )
endif()
