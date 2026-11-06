"""Credential-free discovery with optional, user-supplied authentication.

Pipeline: an engine produces observations (credential-free probes first, authenticated reads only after the user
supplies credentials); fusion builds the stored topology from observations alone; classification and the
credential advisor explain what is known, what is missing and where a login would genuinely help.
"""
