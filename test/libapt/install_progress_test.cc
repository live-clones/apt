#include <config.h>

#include <apt-pkg/install-progress.h>

#include <locale>
#include <string>

#include "common.h"

TEST(InstallProgressTest, FancyGetTextProgressStr)
{
   APT::Progress::PackageManagerFancy p;

   char *originalLocale = setlocale(LC_ALL, "C");
   EXPECT_EQ(60u, p.GetTextProgressStr(0.5, 60).size());
   EXPECT_EQ("##--", p.GetTextProgressStr(0.5, 4));
   EXPECT_EQ("------------", p.GetTextProgressStr(0.0, 12));
   EXPECT_EQ("#-----------", p.GetTextProgressStr(0.1, 12));
   EXPECT_EQ("#####-------", p.GetTextProgressStr(0.4999, 12));
   EXPECT_EQ("######------", p.GetTextProgressStr(0.5001, 12));
   EXPECT_EQ("##########--", p.GetTextProgressStr(0.9001, 12));
   EXPECT_EQ("############", p.GetTextProgressStr(1.0, 12));

   // deal with incorrect inputs gracefully (or should we die instead?)
   EXPECT_EQ("------------", p.GetTextProgressStr(-1.0, 12));
   EXPECT_EQ("############", p.GetTextProgressStr(2.0, 12));

   setlocale(LC_ALL, "C.UTF-8");

   EXPECT_EQ("∎∎——", p.GetTextProgressStr(0.5, 4));
   EXPECT_EQ("————————————", p.GetTextProgressStr(0.0, 12));
   EXPECT_EQ("∎———————————", p.GetTextProgressStr(0.1, 12));
   EXPECT_EQ("∎∎∎∎∎———————", p.GetTextProgressStr(0.4999, 12));
   EXPECT_EQ("∎∎∎∎∎∎——————", p.GetTextProgressStr(0.5001, 12));
   EXPECT_EQ("∎∎∎∎∎∎∎∎∎∎——", p.GetTextProgressStr(0.9001, 12));
   EXPECT_EQ("∎∎∎∎∎∎∎∎∎∎∎∎", p.GetTextProgressStr(1.0, 12));

   // deal with incorrect inputs gracefully (or should we die instead?)
   EXPECT_EQ("————————————", p.GetTextProgressStr(-1.0, 12));
   EXPECT_EQ("∎∎∎∎∎∎∎∎∎∎∎∎", p.GetTextProgressStr(2.0, 12));

   setlocale(LC_ALL, originalLocale);
}
