/*
 * depsolver.cc - The APT 3.0 dependency solver - implementation
 *
 * Copyright (c) 2023 Julian Andres Klode
 * Copyright (c) 2023 Canonical Ltd
 *
 * SPDX-License-Identifier: GPL-2.0+
 *
 * This solver started from scratch but turns slowly into a variant of
 * MiniSat as documented in the paper
 *    "An extensible SAT-solver [extended version 1.2]."
 * by Niklas Eén, and Niklas Sörensson.
 *
 * It extends MiniSAT with support for optional clauses, and differs
 * in that it removes non-deterministic aspects like the activity based
 * ordering. Instead it uses a more nuanced static ordering that, to
 * some extend, preserves some greediness and sub-optimality of the
 * classic APT solver.
 */

#include <config.h>

#include <apt-pkg/algorithms.h>
#include <apt-pkg/aptconfiguration.h>
#include <apt-pkg/cachefilter.h>
#include <apt-pkg/cacheset.h>
#include <apt-pkg/depsolver.h>
#include <apt-pkg/error.h>
#include <apt-pkg/macros.h>
#include <apt-pkg/pkgsystem.h>
#include <apt-pkg/version.h>

#include <sstream>

namespace APT::Solver
{
// FIXME: Helpers stolen from DepCache, please give them back.
struct CompareProviders3 /*{{{*/
{
   pkgCache &Cache;
   pkgDepCache::Policy &Policy;
   pkgCache::PkgIterator const Pkg;
   APT::Solver::DependencySolver &Solver;

   pkgCache::VerIterator bestVersion(pkgCache::PkgIterator pkg)
   {
      pkgCache::VerIterator res = pkg.VersionList();
      for (auto v = res; not v.end(); ++v)
	 res = std::max(res, v, *this);
      return res;
   }
   bool operator()(Var a, Var b)
   {
      pkgCache::VerIterator va = Solver.GetVer(a);
      pkgCache::VerIterator vb = Solver.GetVer(b);
      if (auto pa = Solver.GetPkg(a); not pa.end())
	 va = bestVersion(pa);
      if (auto pb = Solver.GetPkg(b); not pb.end())
	 vb = bestVersion(pb);

      assert(not va.end() && not vb.end());
      return (*this)(va, vb);
   }
   bool operator()(pkgCache::VerIterator const &AV, pkgCache::VerIterator const &BV)
   {
      assert(not AV.end() && not BV.end());
      pkgCache::PkgIterator const A = AV.ParentPkg();
      pkgCache::PkgIterator const B = BV.ParentPkg();
      // Compare versions for the same package. FIXME: Move this to the real implementation
      if (A == B)
      {
	 if (AV == BV)
	    return false;

	 // Candidate wins in upgrade scenario
	 if (Solver.IsUpgrade)
	 {
	    auto Cand = Solver.GetCandidateVer(A);
	    if (AV == Cand || BV == Cand)
	       return (AV == Cand);
	 }

	 // Installed version wins otherwise
	 if (A.CurrentVer() == AV || B.CurrentVer() == BV)
	    return (A.CurrentVer() == AV);

	 // Rest is ordered list, first by priority
	 if (auto pinA = Solver.GetPriority(AV), pinB = Solver.GetPriority(BV); pinA != pinB)
	    return pinA > pinB;

	 // Then by version
	 return _system->VS->CmpVersion(AV.VerStr(), BV.VerStr()) > 0;
      }
      // Try obsolete choices only after exhausting non-obsolete choices such that we install
      // packages replacing them and don't keep back upgrades depending on the replacement to
      // keep the obsolete package installed.
      if (Solver.IsUpgrade)
	 if (auto obsoleteA = Solver.Obsolete(A), obsoleteB = Solver.Obsolete(B); obsoleteA != obsoleteB)
	    return obsoleteB;
      // Prefer MA:same packages if other architectures for it are installed
      if ((AV->MultiArch & pkgCache::Version::Same) == pkgCache::Version::Same ||
	  (BV->MultiArch & pkgCache::Version::Same) == pkgCache::Version::Same)
      {
	 bool instA = false;
	 if ((AV->MultiArch & pkgCache::Version::Same) == pkgCache::Version::Same)
	 {
	    pkgCache::GrpIterator Grp = A.Group();
	    for (pkgCache::PkgIterator P = Grp.PackageList(); P.end() == false; P = Grp.NextPkg(P))
	       if (P->CurrentVer != 0)
	       {
		  instA = true;
		  break;
	       }
	 }
	 bool instB = false;
	 if ((BV->MultiArch & pkgCache::Version::Same) == pkgCache::Version::Same)
	 {
	    pkgCache::GrpIterator Grp = B.Group();
	    for (pkgCache::PkgIterator P = Grp.PackageList(); P.end() == false; P = Grp.NextPkg(P))
	    {
	       if (P->CurrentVer != 0)
	       {
		  instB = true;
		  break;
	       }
	    }
	 }
	 if (instA != instB)
	    return instA;
      }
      if ((A->CurrentVer == 0 || B->CurrentVer == 0) && A->CurrentVer != B->CurrentVer)
	 return A->CurrentVer != 0;
      // Prefer packages in the same group as the target; e.g. foo:i386, foo:amd64
      if (A->Group != B->Group && not Pkg.end())
      {
	 if (A->Group == Pkg->Group && B->Group != Pkg->Group)
	    return true;
	 else if (B->Group == Pkg->Group && A->Group != Pkg->Group)
	    return false;
      }
      // we like essentials
      if ((A->Flags & pkgCache::Flag::Essential) != (B->Flags & pkgCache::Flag::Essential))
      {
	 if ((A->Flags & pkgCache::Flag::Essential) == pkgCache::Flag::Essential)
	    return true;
	 else if ((B->Flags & pkgCache::Flag::Essential) == pkgCache::Flag::Essential)
	    return false;
      }
      if ((A->Flags & pkgCache::Flag::Important) != (B->Flags & pkgCache::Flag::Important))
      {
	 if ((A->Flags & pkgCache::Flag::Important) == pkgCache::Flag::Important)
	    return true;
	 else if ((B->Flags & pkgCache::Flag::Important) == pkgCache::Flag::Important)
	    return false;
      }
      // prefer native architecture
      if (strcmp(A.Arch(), B.Arch()) != 0)
      {
	 if (strcmp(A.Arch(), A.Cache()->NativeArch()) == 0)
	    return true;
	 else if (strcmp(B.Arch(), B.Cache()->NativeArch()) == 0)
	    return false;
	 std::vector<std::string> archs = APT::Configuration::getArchitectures();
	 for (std::vector<std::string>::const_iterator a = archs.begin(); a != archs.end(); ++a)
	    if (*a == A.Arch())
	       return true;
	    else if (*a == B.Arch())
	       return false;
      }
      // higher priority seems like a good idea
      if (AV->Priority != BV->Priority)
	 return AV->Priority < BV->Priority;
      if (auto NameCmp = strcmp(A.Name(), B.Name()))
	 return NameCmp < 0;
      // unable to decide…
      return A->ID > B->ID;
   }
};

/** \brief Returns \b true for packages matching a regular
 *  expression in APT::NeverAutoRemove.
 */
class DefaultRootSetFunc2 : public pkgDepCache::DefaultRootSetFunc
{
   std::unique_ptr<APT::CacheFilter::Matcher> Kernels;

   public:
   DefaultRootSetFunc2(pkgCache *cache) : Kernels(APT::KernelAutoRemoveHelper::GetProtectedKernelsFilter(cache)) {};
   ~DefaultRootSetFunc2() override = default;

   bool InRootSet(const pkgCache::PkgIterator &pkg) override { return pkg.end() == false && ((*Kernels)(pkg) || DefaultRootSetFunc::InRootSet(pkg)); };
}; // FIXME: DEDUP with pkgDepCache.
/*}}}*/

Var DependencySolver::newVar()
{
   auto var = Solver::newVar();
   varPkg.push_back(nullptr);
   varVer.push_back(nullptr);
   return var;
}

Var DependencySolver::GetVar(pkgCache::PkgIterator const &Pkg)
{
   if (pkgVars[Pkg].empty())
   {
      auto var = pkgVars[Pkg] = newVar();
      varPkg[var] = Pkg.MapPointer();
   }
   return pkgVars[Pkg];
}

Var DependencySolver::GetVar(pkgCache::VerIterator const &Ver)
{
   if (verVars[Ver].empty())
   {
      auto var = verVars[Ver] = newVar();
      varVer[var] = Ver.MapPointer();
   }
   return verVars[Ver];
}

DependencySolver::DependencySolver(pkgCache &cache, pkgDepCache::Policy &policy, EDSP::Request::Flags requestFlags)
    : cache(cache),
      policy(policy),
      requestFlags(requestFlags),
      pkgObsolete(cache),
      priorities(cache),
      candidates(cache),
      pkgVars(cache),
      verVars(cache)
{
   // The root variable does not refer to a package or version.
   varPkg.push_back(nullptr);
   varVer.push_back(nullptr);
}

std::string DependencySolver::toString(Var var) const
{
   if (auto P = GetPkg(var); not P.end())
      return P.FullName();
   if (auto V = GetVer(var); not V.end())
      return V.ParentPkg().FullName() + "=" + V.VerStr();
   return "(root)";
}

std::string DependencySolver::toString(Lit lit) const
{
   return (lit.sign() ? "not " : "") + toString(lit.var());
}

std::string DependencySolver::toString(const Clause &clause, bool pretty, bool showMerged) const
{
   std::string out;
   if (showMerged)
      out.append(toString(clause.reason));
   if (clause.dep && pretty)
   {
      out.append(" ").append(pkgCache::DepIterator(cache, static_cast<pkgCache::Dependency *>(clause.dep)).DepType()).append(" ");
      for (auto dep = pkgCache::DepIterator(cache, static_cast<pkgCache::Dependency *>(clause.dep)); not dep.end(); ++dep)
      {
	 out.append(dep.TargetPkg().FullName(true));
	 if (dep.TargetVer())
	    out.append(" (").append(dep.CompType()).append(" ").append(dep.TargetVer()).append(")");
	 if (not(dep->CompareOp & pkgCache::Dep::Or))
	    break;
	 out.append(" | ");
      }
   }
   else if (pretty && clause.group == Group::SelectVersion && clause.negative)
      out.append(" conflicts with other versions of itself");
   else if (pretty && clause.group == Group::SelectVersion && not GetPkg(clause.reason).end())
   {
      out.append(clause.solutions.size() > 1 ? " is available in versions " : " is available in version ");
      for (auto var : clause.solutions)
      {
	 auto ver = GetVer(var);
	 assert(not ver.end());
	 if (var != clause.solutions.front())
	    out.append(", ");
	 out.append(ver.VerStr());
      }
   }
   else
   {
      out.append(" -> ");
      for (auto var : clause.solutions)
	 out.append(" | ").append(toString(var));
   }
   if (showMerged && not clause.merged.empty())
   {
      for (auto &merged : clause.merged)
      {
	 out.append(" and");
	 out.append(toString(merged, pretty, false));
      }
   }
   return out;
}

std::string DependencySolver::DescribeSelection(Var var, bool assignment) const
{
   std::string s;
   if (auto pkg = GetPkg(var); not assignment && not pkg.end() && pkg->CurrentVer)
      strprintf(s, "%s is selected for removal", toString(var).c_str());
   else if (auto ver = GetVer(var); assignment && not ver.end() && ver.ParentPkg().CurrentVer() && ver.ParentPkg().CurrentVer() != ver)
   {
      if (cache.VS->CmpVersion(ver.ParentPkg().CurrentVer().VerStr(), ver.VerStr()) < 0)
	 strprintf(s, "%s is selected as an upgrade", toString(var).c_str());
      else
	 strprintf(s, "%s is selected as a downgrade", toString(var).c_str());
   }
   else if (not assignment)
      strprintf(s, "%s is not selected for install", toString(var).c_str());
   else
      strprintf(s, "%s is selected for install", toString(var).c_str());
   return s;
}

DependencySolver::~DependencySolver() = default;

// This is called in the hot path of Discover() as we are trying to determine if a dependency
// is the same in all packages.
// Marking it constexpr causes it to be inlined, which significantly improves solver performance,
// around 5%; but it produces more LL cache misses.
constexpr bool SameOrGroup(pkgCache::DepIterator a, pkgCache::DepIterator b) noexcept
{
   while (1)
   {
      if (a->DependencyData != b->DependencyData)
	 return false;

      // At least one has reached the end, break
      if (not(a->CompareOp & pkgCache::Dep::Or) || not(b->CompareOp & pkgCache::Dep::Or))
	 break;

      ++a, ++b;
   }
   // Fully iterated over a and b
   return not(a->CompareOp & pkgCache::Dep::Or) && not(b->CompareOp & pkgCache::Dep::Or);
}

const Clause *DependencySolver::RegisterClause(Clause &&clause)
{
   auto &clauses = (*this)[clause.reason].clauses;
   pkgCache::DepIterator dep(cache, static_cast<pkgCache::Dependency *>(clause.dep));

   // Merge dependencies on the same name into a single one, and restrict their solution space.
   // For example, given dependencies on
   //	 bar Depends: pkg (<< 3), pkg (>> 2)
   //	 foo Provides: pkg (= 1)
   // The solution must always be pkg (= 2) and not say pkg (= 3), foo.
   // FIXME: This would be nice to merge across or groups too, but we can't do that yet.
   if (not clause.negative && not dep.end() && not(dep->CompareOp & pkgCache::Dep::Or))
   {
      bool merged = false;
      for (auto const &earlierClause : clauses)
      {
	 if (earlierClause->negative)
	    continue;
	 // Skip dependencies with or groups or dependencies on different names
	 if (pkgCache::DepIterator earlierDep(cache, static_cast<pkgCache::Dependency *>(earlierClause->dep));
	     earlierDep.end() || (earlierDep->CompareOp & pkgCache::Dep::Or) ||
	     earlierDep.TargetPkg() != dep.TargetPkg())
	    continue;
	 if (std::none_of(earlierClause->solutions.begin(), earlierClause->solutions.end(), [&clause](auto earlierSol) noexcept
			  { return std::ranges::contains(clause.solutions,
							 earlierSol); }))
	    continue;

	 if (earlierClause->optional == clause.optional)
	 {
	    std::erase_if(earlierClause->solutions, [&clause, this](auto earlierSol) noexcept
			  { return not std::ranges::contains(clause.solutions,
							     earlierSol); });

	    earlierClause->merged.push_front(clause);
	    merged = true;
	 }
	 else if (clause.optional)
	 {
	    // If say a Depends has fewer solution than a Recommends, remove the Recommend's extranous ones.
	    std::erase_if(clause.solutions, [&earlierClause, this](auto sol) noexcept
			  { return not std::ranges::contains(earlierClause->solutions,
							     sol); });

	    // Remove recursion here, such that we display correctly (if we ever display anywhere...)
	    auto earlierClauseCopy = *earlierClause;
	    clause.merged = std::move(earlierClauseCopy.merged);
	    clause.merged.push_front(earlierClauseCopy);
	 }
      }

      if (merged)
	 return nullptr;
   }

   clauses.push_back(std::make_unique<Clause>(std::move(clause)));
   auto const &inserted = clauses.back();
   // Insert all our watches
   if (not inserted->reason.empty())
      watches(inserted->reason).push_back(inserted.get());
   for (auto sol : inserted->solutions)
      watches(inserted->negative ? sol : ~sol).push_back(inserted.get());
   return inserted.get();
}

// This is essentially asking whether any other binary in the source package has a higher candidate
// version. This pretends that each package is installed at the same source version as the package
// under consideration.
bool DependencySolver::ObsoletedByNewerSourceVersion(pkgCache::VerIterator cand) const
{
   const auto pkg = cand.ParentPkg();
   const int candPriority = GetPriority(cand);

   for (auto ver = cand.Cache()->FindGrp(cand.SourcePkgName()).VersionsInSource(); not ver.end(); ver = ver.NextInSource())
   {
      // We are only interested in other packages in the same source package; built for the same architecture.
      if (ver->ParentPkg == cand->ParentPkg || ver.ParentPkg()->Arch != cand.ParentPkg()->Arch ||
	  (ver->MultiArch & pkgCache::Version::All) != (cand->MultiArch & pkgCache::Version::All) ||
	  cache.VS->CmpVersion(ver.SourceVerStr(), cand.SourceVerStr()) <= 0)
	 continue;

      // We also take equal priority here, given that we have a higher version
      const int priority = GetPriority(ver);
      if (priority == 0 || priority < candPriority)
	 continue;

      pkgObsolete[pkg] = LiftedBool::True;
      if (debug >= 3)
	 std::cerr << "Obsolete: " << cand.ParentPkg().FullName() << "=" << cand.VerStr() << " due to " << ver.ParentPkg().FullName() << "=" << ver.VerStr() << "\n";
      return true;
   }

   return false;
}

bool DependencySolver::Obsolete(pkgCache::PkgIterator pkg, bool AllowManual) const
{
   if (auto var = FindVar(pkg); not var.empty() && (*this)[var].flags.manual && not AllowManual)
      return false;
   if (pkgObsolete[pkg] != LiftedBool::Undefined)
      return pkgObsolete[pkg] == LiftedBool::True;

   auto ver = GetCandidateVer(pkg);

   if (ver.end() && not StrictPinning)
      ver = pkg.VersionList();
   if (ver.end())
   {
      if (debug >= 3)
	 std::cerr << "Obsolete: " << pkg.FullName() << " - not installable\n";
      pkgObsolete[pkg] = LiftedBool::True;
      return true;
   }

   if (ObsoletedByNewerSourceVersion(ver))
      return true;

   // Any version downloadable is good enough for us tbh
   for (auto ver = pkg.VersionList(); not ver.end(); ++ver)
   {
      if (ver.Downloadable())
      {
	 pkgObsolete[pkg] = LiftedBool::False;
	 return false;
      }
   }

   if (debug >= 3)
      std::cerr << "Obsolete: " << ver.ParentPkg().FullName() << "=" << ver.VerStr() << " - not installable\n";
   pkgObsolete[pkg] = LiftedBool::True;
   return true;
}
void DependencySolver::Discover(Var var)
{
   assert(discoverQ.empty());
   discoverQ.push(var);

   while (not discoverQ.empty())
   {
      var = discoverQ.front();
      discoverQ.pop();

      // Package needs to be discovered before the version to be able to dedup shared dependencies
      if (auto Ver = GetVer(var); not Ver.end() && not(*this)[Ver.ParentPkg()].flags.discovered)
	 var = GetVar(Ver.ParentPkg());

      // NB: Do not hold a reference to the variable's state here; discovering
      // the dependencies below registers new variables, which may reallocate.
      if ((*this)[var].flags.discovered)
	 continue;

      (*this)[var].flags.discovered = true;

      if (auto Pkg = GetPkg(var); not Pkg.end())
      {
	 Clause clause{GetVar(Pkg), Group::SelectVersion};
	 for (auto ver = Pkg.VersionList(); not ver.end(); ver++)
	    clause.solutions.push_back(GetVar(ver));

	 std::stable_sort(clause.solutions.begin(), clause.solutions.end(), CompareProviders3{cache, policy, Pkg, *this});
	 RegisterClause(std::move(clause));

	 RegisterCommonDependencies(Pkg);
      }
      else if (auto Ver = GetVer(var); not Ver.end())
      {
	 Clause clause{GetVar(Ver), Group::SelectVersion};
	 clause.solutions = {GetVar(Ver.ParentPkg())};
	 RegisterClause(std::move(clause));

	 for (auto OV = Ver.ParentPkg().VersionList(); not OV.end(); ++OV)
	 {
	    if (OV == Ver)
	       continue;

	    Clause clause{GetVar(Ver), Group::SelectVersion, false, true /* negative */};
	    clause.solutions = {GetVar(OV)};
	    RegisterClause(std::move(clause));
	 }

	 if (UpgradeBySourcePackage && Ver != Ver.ParentPkg().CurrentVer())
	 {
	    // For this version selection, if I have other binaries in the source package that are currently installed,
	    // mark them for upgrade using an eager optional dependency (which is executed soon, but can be skipped)
	    for (auto sibling = Ver.SourceVersion().Group().VersionsInSource(); not sibling.end(); sibling = sibling.NextInSource())
	    {
	       // Package is the same; not installed or at right version, don't need to upgrade
	       if (sibling->ParentPkg == Ver->ParentPkg || not sibling.ParentPkg()->CurrentVer || sibling.ParentPkg().CurrentVer() == sibling)
		  continue;
	       // Package has a different source version than us, so it's not relevant
	       if (strcmp(sibling.SourceVersion().VerStr(), Ver.SourceVersion().VerStr()) != 0)
		  continue;
	       Clause clause{GetVar(Ver), Group::SelectVersion, true /* optional */};
	       clause.eager = true;
	       clause.solutions = {GetVar(sibling)};
	       RegisterClause(std::move(clause));
	    }
	 }

	 for (auto dep = Ver.DependsList(); not dep.end();)
	 {
	    // Compute a single dependency element (glob or)
	    pkgCache::DepIterator start;
	    pkgCache::DepIterator end;
	    dep.GlobOr(start, end); // advances dep

	    // This dependency is shared across all versions, skip it.
	    if (auto &pkgClauses = (*this)[Ver.ParentPkg()].clauses;
		std::any_of(pkgClauses.begin(), pkgClauses.end(), [this, start](auto &c)
			    { return c->dep && SameOrGroup(start, pkgCache::DepIterator(cache, static_cast<pkgCache::Dependency *>(c->dep))); }))
	       continue;

	    if (auto clause = TranslateOrGroup(start, end, GetVar(Ver)))
	       RegisterClause(std::move(*clause));
	 }
      }

      // Recursively discover everything else that is not already FALSE by fact (False at level 0)
      for (auto const &clause : (*this)[var].clauses)
	 for (auto const &var : clause->solutions)
	    if (value(var) != LiftedBool::False || (*this)[var].level > 0)
	       discoverQ.push(var);
   }
}

void DependencySolver::RegisterCommonDependencies(pkgCache::PkgIterator Pkg)
{
   for (auto dep = Pkg.VersionList().DependsList(); not dep.end();)
   {
      pkgCache::DepIterator start, end;
      dep.GlobOr(start, end); // advances dep

      bool allHaveDep = true;
      for (auto ver = ++Pkg.VersionList(); allHaveDep && not ver.end(); ver++)
      {
	 bool haveDep = false;
	 for (auto otherDep = ver.DependsList(); not haveDep && not otherDep.end();)
	 {
	    pkgCache::DepIterator otherStart, otherEnd;
	    otherDep.GlobOr(otherStart, otherEnd); // advances other dep
	    haveDep = SameOrGroup(start, otherStart);
	 }
	 if (not haveDep)
	    allHaveDep = false;
      }
      if (not allHaveDep)
	 continue;
      if (auto clause = TranslateOrGroup(start, end, GetVar(Pkg)))
	 RegisterClause(std::move(*clause));
   }
}

std::optional<Clause> DependencySolver::TranslateOrGroup(pkgCache::DepIterator start, pkgCache::DepIterator end, Var reason)
{
   // Non-important dependencies can only be installed if they are currently satisfied, see the check further
   // below once we have calculated all possible solutions.
   if (start.ParentPkg()->CurrentVer == 0 && not policy.IsImportantDep(start))
      return std::nullopt;
   // Replaces and Enhances are not a real dependency.
   if (start->Type == pkgCache::Dep::Replaces || start->Type == pkgCache::Dep::Enhances)
      return std::nullopt;
   if (unlikely(debug >= 3))
      std::cerr << "Found dependency critical " << toString(reason) << " -> " << start.TargetPkg().FullName() << "\n";

   Clause clause{reason, Group::Satisfy, not start.IsCritical() /* optional */, start.IsNegative()};

   clause.dep = start;

   do
   {
      auto begin = clause.solutions.size();

      if (DeferVersionSelection && not start.IsNegative() && start.TargetPkg().ProvidesList().end() && start.IsSatisfied(start.TargetPkg()))
      {
	 clause.solutions.push_back(GetVar(start.TargetPkg()));
      }
      else
      {
	 std::unique_ptr<pkgCache::Version *[]> all(start.AllTargets());

	 for (auto tgt = all.get(); *tgt; ++tgt)
	 {
	    pkgCache::VerIterator tgti(cache, *tgt);

	    if (unlikely(debug >= 3))
	       std::cerr << "Adding work to  item " << toString(reason) << " -> " << tgti.ParentPkg().FullName() << "=" << tgti.VerStr() << (clause.negative ? " (negative)" : "") << "\n";
	    clause.solutions.push_back(GetVar(tgti));
	 }
	 std::stable_sort(clause.solutions.begin() + begin, clause.solutions.end(), CompareProviders3{cache, policy, start.TargetPkg(), *this});
      }
      if (start == end)
	 break;
      ++start;
   } while (1);

   // Move obsolete packages to the end, and (non-obsolete) installed packages to the front
   if (not FixPolicyBroken)
      std::stable_sort(clause.solutions.begin(), clause.solutions.end(), [this](Var a, Var b)
		       {
	    if (IsUpgrade)
	       if (auto obsoleteA = Obsolete(AsPkg(a)), obsoleteB = Obsolete(AsPkg(b)); obsoleteA != obsoleteB)
		  return obsoleteB;
	    if ((AsPkg(a)->CurrentVer == 0 || AsPkg(b)->CurrentVer == 0) && AsPkg(a)->CurrentVer != AsPkg(b)->CurrentVer)
	       return AsPkg(a)->CurrentVer != 0;
	    return false; });

   if (std::all_of(clause.solutions.begin(), clause.solutions.end(), [this](auto var) -> auto
		   { return AsPkg(var)->CurrentVer == 0; }))
      clause.group = Group::SatisfyNew;
   if (std::any_of(clause.solutions.begin(), clause.solutions.end(), [this](auto var) -> auto
		   { return Obsolete(AsPkg(var), true); }))
      clause.group = Group::SatisfyObsolete;
   // Try to perserve satisfied Recommends. FIXME: We should check if the Recommends was there in the installed version?
   if (clause.optional && start.ParentPkg()->CurrentVer)
   {
      bool important = policy.IsImportantDep(start);
      auto importantToKeep = [this](pkgCache::DepIterator d)
      {
	 return policy.IsImportantDep(d) || (KeepRecommends && d->Type == pkgCache::Dep::Recommends) || (KeepSuggests && d->Type == pkgCache::Dep::Suggests);
      };
      bool satisfied = std::any_of(clause.solutions.begin(), clause.solutions.end(), [this](auto var)
				   { return GetPkg(var) ? GetPkg(var)->CurrentVer != nullptr : GetVer(var) == AsPkg(var).CurrentVer(); });

      // Find the existing dependency
      pkgCache::DepIterator existing;
      for (auto D = start.ParentPkg().CurrentVer().DependsList(); not D.end(); D++)
	 if (not D.IsCritical() && importantToKeep(D) && D.TargetPkg() == start.TargetPkg())
	 {
	    existing = D;
	    break;
	 }

      if (not existing.end() && not important && importantToKeep(start) && satisfied)
      {
	 if (unlikely(debug >= 3))
	    std::cerr << "Try to keep satisfied: " << toString(clause, true) << std::endl;
	 clause.group = Group::SatisfySuggests;
	 // Erase the non-installed solutions. We will process this last and try to keep the previously installed
	 // "best" solution installed.
	 clause.solutions.erase(std::remove_if(clause.solutions.begin(), clause.solutions.end(), [this](auto var)
					       { return AsPkg(var)->CurrentVer == nullptr; }),
				clause.solutions.end());
      }
      else if (not important)
      {
	 if (unlikely(debug >= 3))
	    std::cerr << "Ignore unimportant clause: " << toString(clause, true) << std::endl;
	 return std::nullopt;
      }
      else if (not existing.end() && policy.IsImportantDep(existing) && not satisfied)
      {
	 if (unlikely(debug >= 3))
	    std::cerr << "Ignoring unsatisfied clause: " << toString(clause, true) << std::endl;
	 return std::nullopt;
      }
      else if (IsUpgrade && not existing.end() && satisfied)
      {
	 if (unlikely(debug >= 3))
	    std::cerr << "Promoting previously satisfied clause to hard dependency: " << toString(clause, true) << std::endl;
	 clause.optional = false;
	 clause.eager = true;
      }
      else if (
	 IsUpgrade && not(AllowRemove && AllowInstall)			   // promote Recommends to Depends in upgrade, not in dist-upgrade.
	 && GetVer(reason) && GetVer(reason) != AsPkg(reason).CurrentVer() // and if this an upgrade to an installed package
	 && (existing.end() || not policy.IsImportantDep(existing))	   // new Recommends, or upgraded from Suggests
      )
      {
	 if (unlikely(debug >= 3))
	    std::cerr << "Promoting new clause to hard dependency: " << toString(clause) << std::endl;
	 clause.optional = false;
	 clause.eager = true;
      }
      else if (not existing.end() && importantToKeep(start) && satisfied)
      {
	 if (unlikely(debug >= 3))
	    std::cerr << "Restricting existing Recommends to installed packages: " << toString(clause, true) << std::endl;
	 // Erase the non-installed solutions. We will process this last and try to keep the previously installed
	 // "best" solution installed.
	 clause.solutions.erase(std::remove_if(clause.solutions.begin(), clause.solutions.end(), [this](auto var)
					       { return AsPkg(var)->CurrentVer == nullptr; }),
				clause.solutions.end());
	 clause.eager = true;
      }
   }

   return clause;
}

// \brief Apply the selections from the dep cache to the solver
bool DependencySolver::FromDepCache(pkgDepCache &depcache)
{
   DefaultRootSetFunc2 rootSet(&cache);
   std::vector<Var> manualPackages;
   std::vector<Var> removals;

   // Enforce strict pinning rules by rejecting all forbidden versions.
   if (StrictPinning)
   {
      for (auto P = cache.PkgBegin(); not P.end(); P++)
      {
	 bool isForced = depcache[P].Protect() && depcache[P].Install();
	 bool isPhasing = IsUpgrade && depcache.PhasingApplied(P) && not isForced;
	 for (auto V = P.VersionList(); not V.end(); ++V)
	    if (P.CurrentVer() != V && (depcache.GetCandidateVersion(P) != V || isPhasing))
	       if (not Enqueue(~GetVar(V), {}))
		  return false;
      }
   }

   // Clause discovery depends on the manual flag, so we need to set the manual flag first before we discover any packages
   for (auto P = cache.PkgBegin(); not P.end(); P++)
      if (P->CurrentVer && not(depcache[P].Flags & pkgCache::Flag::Auto) && (depcache[P].Keep() || depcache[P].Install()))
	 (*this)[P].flags.manual = true;

   for (auto P = cache.PkgBegin(); not P.end(); P++)
   {
      if (P->VersionList == nullptr)
	 continue;

      auto state = depcache[P];
      if (P->SelectedState == pkgCache::State::Hold && not state.Protect())
      {
	 if (unlikely(debug >= 1))
	    std::cerr << "Hold " << P.FullName() << "\n";
	 if (P->CurrentVer ? not Enqueue(GetVar(P.CurrentVer())) : not Enqueue(~GetVar(P)))
	    return false;
      }
      else if (state.Delete()						  // Normal delete request.
	       || (not P->CurrentVer && state.Keep() && state.Protect())  // Delete request of not installed package.
	       || (not P->CurrentVer && state.Keep() && not AllowInstall) // New package installs not allowed.
      )
      {
	 auto Protected = state.Protect() || (not P->CurrentVer && not AllowInstall);
	 if (unlikely(debug >= 1))
	    std::cerr << "Delete " << P.FullName() << "\n";
	 if (Protected)
	 {
	    if (not Enqueue(~GetVar(P)))
	       return false;
	 }
	 else
	    removals.push_back(GetVar(P));
      }
      else if (state.Install() || (state.Keep() && P->CurrentVer))
      {
	 auto isEssential = P->Flags & (pkgCache::Flag::Essential | pkgCache::Flag::Important);
	 auto isAuto = (depcache[P].Flags & pkgCache::Flag::Auto);
	 auto isOptional = ((isAuto && AllowRemove) || AllowRemoveManual) && not isEssential && not depcache[P].Protect();
	 auto Root = rootSet.InRootSet(P);
	 auto Upgrade = depcache.GetCandidateVersion(P) != P.CurrentVer();
	 auto Group = isAuto ? (Upgrade ? Group::UpgradeAuto : Group::KeepAuto)
			     : (Upgrade ? Group::UpgradeManual : Group::InstallManual);

	 if (isAuto && not depcache[P].Protect() && not isEssential && not KeepAuto && not rootSet.InRootSet(P))
	 {
	    if (unlikely(debug >= 1))
	       std::cerr << "Ignore automatic install " << P.FullName() << " (" << (isEssential ? "E" : "") << (isAuto ? "M" : "") << (Root ? "R" : "") << ")"
			 << "\n";
	    continue;
	 }
	 if (unlikely(debug >= 1))
	    std::cerr << "Install " << P.FullName() << " (" << (isEssential ? "E" : "") << (isAuto ? "M" : "") << (Root ? "R" : "") << ")"
		      << "\n";
	 if (not isOptional)
	 {
	    // Pre-empt the non-optional requests, as we don't want to queue them, we can just "unit propagate" here.
	    if (depcache[P].Keep() ? not Enqueue(GetVar(P)) : not Enqueue(GetVar(depcache.GetCandidateVersion(P))))
	       return false;
	 }
	 else
	 {
	    Clause w{Var(), Group, isOptional};
	    w.solutions.push_back(GetVar(P));
	    auto insertedW = RegisterClause(std::move(w));
	    if (insertedW && not AddWork(Work{insertedW, decisionLevel()}))
	       return false;

	    if (not isAuto)
	       manualPackages.push_back(GetVar(P));

	    // Given A->A2|A1, B->B1|B2; Bn->An, if we select `not A1`, we
	    // should try to install A2 before trying B so we end up with
	    // A2, B2, instead of removing A1 to keep B1 installed. This
	    // requires some special casing in Work::operator< above.
	    // Compare test-bug-712116-dpkg-pre-install-pkgs-hook-multiarch
	    Clause shortcircuit{Var(), Group, isOptional};
	    for (auto V = P.VersionList(); not V.end(); ++V)
	       shortcircuit.solutions.push_back(GetVar(V));
	    std::stable_sort(shortcircuit.solutions.begin(), shortcircuit.solutions.end(), CompareProviders3{cache, policy, P, *this});
	    auto insertedShort = RegisterClause(std::move(shortcircuit));
	    if (insertedShort && not AddWork(Work{insertedShort, decisionLevel()}))
	       return false;

	    // Discovery here is needed so the shortcircuit clause can actually become unit.
	    if (P.VersionList() && P.VersionList()->NextVer)
	       Discover(GetVar(P));
	 }
      }
      else if (IsUpgrade && AllowRemove && AllowInstall && (P->Flags & pkgCache::Flag::Essential))
      {
	 Clause w{Var(), Group::InstallManual, false};
	 auto G = P.Group();
	 for (auto P = G.PackageList(); not P.end(); P = G.NextPkg(P))
	    if (P->Flags & pkgCache::Flag::Essential)
	       w.solutions.push_back(GetVar(P));
	 std::stable_sort(w.solutions.begin(), w.solutions.end(), CompareProviders3{cache, policy, P, *this});
	 if (unlikely(debug >= 1))
	    std::cerr << "Install essential package " << P << std::endl;
	 auto inserted = RegisterClause(std::move(w));
	 if (inserted && not AddWork(Work{inserted, decisionLevel()}))
	    return false;
      }
   }

   if (not Propagate())
      return false;

   std::stable_sort(manualPackages.begin(), manualPackages.end(), CompareProviders3{cache, policy, {}, *this});
   for (auto assumption : manualPackages)
   {
      if (not Assume(assumption, {}) || not Propagate())
	 must_succeed(Pop());
   }
   for (auto removal : removals)
   {
      if (not Assume(~removal, {}) || not Propagate())
	 must_succeed(Pop());
   }

   return true;
}

bool DependencySolver::ToDepCache(pkgDepCache &depcache) const
{
   FastContiguousCacheMap<pkgCache::Package, bool> movedManual(cache);
   pkgDepCache::ActionGroup group(depcache);
   for (auto P = cache.PkgBegin(); not P.end(); P++)
   {
      depcache[P].Marked = 0;
      depcache[P].Garbage = 0;
      auto var = FindVar(P);
      if (not var.empty() && value(var) == LiftedBool::True)
      {
	 Var candVar;
	 pkgCache::VerIterator cand;
	 for (auto V = P.VersionList(); cand.end() && not V.end(); V++)
	    if (auto verVar = FindVar(V); not verVar.empty() && value(verVar) == LiftedBool::True)
	       cand = V, candVar = verVar;

	 auto reasonClause = cand.end() ? nullptr : (*this)[candVar].reason;
	 auto reason = reasonClause ? reasonClause->reason : Var();
	 if (auto RP = GetPkg(reason); not RP.end() && RP == P)
	    reason = (*this)[var].reason ? (*this)[var].reason->reason : Var();

	 if (cand != P.CurrentVer())
	 {
	    bool automatic = (not reason.empty() || (depcache[P].Flags & pkgCache::Flag::Auto)) && not movedManual[P];
	    depcache.SetCandidateVersion(cand);
	    depcache.MarkInstall(P, false, 0, not automatic);

	    // Set the automatic bit for new packages or move it on upgrades to oldlibs
	    if (not P->CurrentVer)
	       depcache.MarkAuto(P, automatic);
	    else if (not(depcache[P].Flags & pkgCache::Flag::Auto) && P.CurrentVer()->Section && cand->Section && not _config->SectionInSubTree("APT::Move-Autobit-Sections", P.CurrentVer().Section()) && _config->SectionInSubTree("APT::Move-Autobit-Sections", cand.Section()))
	    {
	       bool moved = false;
	       for (auto const &clause : (*this)[candVar].clauses)
		  for (auto sol : clause->solutions)
		  {
		     // New installs move the auto-bit. TODO: Should we look at whether clause is the reason for installing it?
		     if (AsPkg(sol) == P || AsPkg(sol)->CurrentVer)
			continue;
		     std::cerr << "Move  manual bit from " << P.FullName() << " to " << AsPkg(sol).Name() << std::endl;
		     movedManual[AsPkg(sol)] = true;
		     depcache.MarkAuto(AsPkg(sol), false);
		     moved = true;
		  }
	       if (moved)
		  depcache.MarkAuto(P, true);
	    }
	 }
	 else
	    depcache.MarkKeep(P, false, reason.empty() && not(depcache[P].Flags & pkgCache::Flag::Auto));

	 depcache[P].Marked = 1;
	 depcache[P].Garbage = 0;
      }
      else if (P->CurrentVer || depcache[P].Install())
      {
	 bool automatic = var.empty() || ((not(*this)[var].reason) && (not(*this)[var].reasonStr));
	 depcache.MarkDelete(P, false, 0, automatic);
	 depcache[P].Marked = 0;
	 depcache[P].Garbage = 1;
      }
   }
   return true;
}

// Command-line
std::string DependencySolver::InternalCliWhy(pkgDepCache &cache, pkgCache::PkgIterator pkg, bool assignment)
{
   DependencySolver solver(cache.GetCache(), cache.GetPolicy(), EDSP::Request::Flags(0));
   std::string buf;

   auto doOne = [&](Var var) -> std::string
   {
      solver.Discover(var);
      if (not solver.FromDepCache(cache) || not solver.Solve())
	 return "";
      std::unordered_set<Var> seen;
      if (solver[var].assignment == LiftedBool::Undefined)
	 return strprintf(buf, "%s is undecided\n", solver.toString(var).c_str()), buf;
      if (assignment && solver[var].assignment != LiftedBool::True)
	 return strprintf(buf, "%s is not actually marked for install\n", solver.toString(var).c_str()), buf;
      if (not assignment && solver[var].assignment == LiftedBool::True)
	 return strprintf(buf, "%s is actually marked for install\n", solver.toString(var).c_str()), buf;
      return solver.LongWhyStr(var, assignment, solver[var].reason, "", seen);
   };

   if (pkg.VersionList().end())
   {
      if (pkg.ProvidesList().end())
	 return strprintf(buf, "%s is a virtual package without a provider\n", pkg.FullName().c_str()), buf;

      std::ostringstream out;
      ioprintf(out, "%s is a virtual package, printing all providers\n", pkg.FullName().c_str());
      for (auto prv = pkg.ProvidesList(); not prv.end(); ++prv)
	 out << doOne(solver.GetVar(prv.OwnerVer()));
      return out.str();
   }
   return doOne(solver.GetVar(pkg));
}
} // namespace APT::Solver
