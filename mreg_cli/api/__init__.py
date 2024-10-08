"""API glue code for the mreg_cli package.

Originally the API code took whatever JSON data it received and returned it as a dictionary.
This led to horrible code that was hard to maintain and debug. This module is an attempt to
fix that by using pydantic models to validate incoming data so the client code has
guarantees about the data it is working with.
"""
