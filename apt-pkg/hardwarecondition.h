// -*- mode: cpp; mode: fold -*-
#ifndef APT_HARDWARECONDITION_H
#define APT_HARDWARECONDITION_H

#include <apt-pkg/header-is-private.h>
#include <apt-pkg/pkgcache.h>

#include <string_view>

namespace APT::HardwareCondition
{
APT_HIDDEN bool Evaluate(std::string_view field);
APT_HIDDEN bool IsSatisfied(pkgCache::VerIterator const &Ver);
}

#endif
