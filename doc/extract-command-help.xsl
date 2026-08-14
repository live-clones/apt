<?xml version="1.0" encoding="utf-8"?>
<!--
  extract-command-help.xsl

  Extracts per-command help text from apt.8.xml as plain text.
  Output format: one record per line, tab-separated:
    command TAB description

  Entities like apt-get are resolved by xsltproc via the DTD.
  DocBook markup (option, literal, command, para) is stripped to plain text.
-->
<xsl:stylesheet version="1.0"
		xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:output method="text" encoding="utf-8" omit-xml-declaration="yes"/>

  <!-- Skip everything by default -->
  <xsl:template match="text()"/>

  <!-- Process only the Description variablelist -->
  <xsl:template match="/refentry/refsect1[title='Description']/variablelist">
    <xsl:apply-templates select="varlistentry" mode="cmd"/>
  </xsl:template>

  <!-- Each varlistentry: extract command name(s) and description text -->
  <xsl:template match="varlistentry" mode="cmd">
    <xsl:variable name="desc">
      <xsl:apply-templates select="listitem" mode="extract"/>
    </xsl:variable>
    <!-- Only output if there is actual description text -->
    <xsl:if test="normalize-space($desc)">
      <xsl:for-each select="term/option">
	<xsl:value-of select="."/>
	<xsl:text>&#9;</xsl:text>
	<xsl:value-of select="normalize-space($desc)"/>
	<xsl:text>&#10;</xsl:text>
      </xsl:for-each>
    </xsl:if>
  </xsl:template>

  <!-- Extract mode: convert DocBook elements to plain text -->
  <xsl:template match="para" mode="extract">
    <xsl:apply-templates mode="extract"/>
    <xsl:text> </xsl:text>
  </xsl:template>

  <xsl:template match="simpara" mode="extract">
    <xsl:apply-templates mode="extract"/>
    <xsl:text> </xsl:text>
  </xsl:template>

  <!-- Strip markup, keep text content -->
<xsl:template match="option|literal|command|filename|replaceable|abbrev|ulink|citerefentry|refentrytitle|envar" mode="extract">    <xsl:apply-templates mode="extract"/>
  </xsl:template>

  <!-- For citerefentry, just output the refentrytitle text -->
  <xsl:template match="citerefentry" mode="extract">
    <xsl:value-of select="refentrytitle"/>
  </xsl:template>

  <!-- Default text passthrough in extract mode -->
  <xsl:template match="text()" mode="extract">
    <xsl:value-of select="."/>
  </xsl:template>

</xsl:stylesheet>
