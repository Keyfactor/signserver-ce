<?xml version="1.0" encoding="utf-8"?>
<!--
   Licensed to the Apache Software Foundation (ASF) under one or more
   contributor license agreements.  See the NOTICE file distributed with
   this work for additional information regarding copyright ownership.
   The ASF licenses this file to You under the Apache License, Version 2.0
   (the "License"); you may not use this file except in compliance with
   the License.  You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.



Copyright (c) 2006, Wygwam
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
Neither the name of WYGWAM nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
-->
<xsl:stylesheet version="1.0"
	xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
	xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
	<xsl:output method="html" />

	<!-- Document root -->
	<xsl:template match="/w:document">
		<xsl:apply-templates select="w:body" />
	</xsl:template>

	<!-- Body and paragraphs -->
	<xsl:template match="w:body">
		<html>
			<body>
				<xsl:for-each select="w:p">
					<p>
						<xsl:apply-templates select="w:pPr" />
						<xsl:apply-templates select="w:r" />
					</p>
				</xsl:for-each>
			</body>
		</html>
	</xsl:template>

	<!--  Paragraph properties -->
	<xsl:template match="w:pPr">
		<xsl:attribute name="style">
			<xsl:apply-templates />
		</xsl:attribute>
	</xsl:template>

	<!-- Text alignment -->
	<xsl:template match="w:jc">
		text-align:
		<xsl:value-of select="@w:val" />
	</xsl:template>

	<!-- Run -->
	<xsl:template match="w:r">
		<span>
			<xsl:apply-templates select="w:rPr" />
			<xsl:value-of select="w:t" />
		</span>
	</xsl:template>

	<!-- Run properties -->
	<xsl:template match="w:rPr">
		<xsl:attribute name="style">
			<xsl:apply-templates />
		</xsl:attribute>
	</xsl:template>

	<!--  Font size -->
	<xsl:template match="w:sz">
		font-size:
		<xsl:value-of select="@w:val" />
		px;
	</xsl:template>
	
	<!-- Vertical alignment -->
	<xsl:template match="w:vertAlign">
		<xsl:variable name="jcVal" select="@w:val" />
		<xsl:if test="$jcVal = 'superscript'">
			font-size:33%;position:relative;bottom:0.5em;
		</xsl:if>
		<xsl:if test="$jcVal = 'subscript'">
			font-size:33%;position:relative;bottom:-0.5em;
		</xsl:if>
	</xsl:template>

	<!-- Bold -->
	<xsl:template match="w:b">font-weight:bold;</xsl:template>

	<!-- Italic -->
	<xsl:template match="w:i">font-style:italic;</xsl:template>

	<!-- Underline -->
	<xsl:template match="w:u">text-decoration:underline;</xsl:template>

</xsl:stylesheet>
