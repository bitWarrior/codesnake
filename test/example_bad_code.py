#!/usr/bin/env python3
"""
Example file with various code issues for testing the semantic checker.
This file intentionally contains multiple code smells and anti-patterns.
"""

import os
from subprocess import call
from pickle import loads  # Security issue


# Security Issues

def dangerous_eval(user_input):
    """SEC001: Using eval with user input"""
    result = eval(user_input)  # DANGEROUS!
    return result


def dangerous_exec(code):
    """SEC001: Using exec"""
    exec(code)  # DANGEROUS!


def unsafe_subprocess():
    """SEC003: Shell injection vulnerability"""
    user_file = input("Enter filename: ")
    call(f"cat {user_file}", shell=True)  # DANGEROUS!


# Mutable Default Arguments (BUG001)

def append_to_list(item, lst=[]):  # BUG! Mutable default
    """BUG001: Mutable default argument"""
    lst.append(item)
    return lst


def add_to_dict(key, value, d={}):  # BUG! Mutable default
    """BUG001: Another mutable default"""
    d[key] = value
    return d


# Exception Handling Issues

def bare_except():
    """EXC001: Bare except clause"""
    try:
        risky_operation()
    except:  # TOO BROAD!
        pass  # EXC003: Empty except


def catch_all_exceptions():
    """EXC002: Catching Exception is too broad"""
    try:
        something()
    except Exception:  # Too broad
        print("Error occurred")


def raise_without_message():
    """EXC004: Raising exception without message"""
    if True:
        raise Exception()  # No message!


# Complexity Issues

def too_many_parameters(a, b, c, d, e, f, g, h, i):  # COMP001: Too many parameters
    """COMP001: Function with too many parameters"""
    return a + b + c + d + e + f + g + h + i


def high_complexity(x):
    """COMP002: High cyclomatic complexity"""
    if x > 0:
        if x > 10:
            if x > 20:
                if x > 30:
                    if x > 40:
                        if x > 50:
                            if x > 60:
                                if x > 70:
                                    if x > 80:
                                        if x > 90:
                                            return "very high"
                                        return "high"
                                    return "medium-high"
                                return "medium"
                            return "medium-low"
                        return "low-medium"
                    return "low"
                return "very low"
            return "minimal"
        return "tiny"
    return "zero"


def very_long_function():
    """COMP003: Function that's too long"""
    line1 = 1
    line2 = 2
    line3 = 3
    line4 = 4
    line5 = 5
    line6 = 6
    line7 = 7
    line8 = 8
    line9 = 9
    line10 = 10
    line11 = 11
    line12 = 12
    line13 = 13
    line14 = 14
    line15 = 15
    line16 = 16
    line17 = 17
    line18 = 18
    line19 = 19
    line20 = 20
    line21 = 21
    line22 = 22
    line23 = 23
    line24 = 24
    line25 = 25
    line26 = 26
    line27 = 27
    line28 = 28
    line29 = 29
    line30 = 30
    line31 = 31
    line32 = 32
    line33 = 33
    line34 = 34
    line35 = 35
    line36 = 36
    line37 = 37
    line38 = 38
    line39 = 39
    line40 = 40
    line41 = 41
    line42 = 42
    line43 = 43
    line44 = 44
    line45 = 45
    line46 = 46
    line47 = 47
    line48 = 48
    line49 = 49
    line50 = 50
    line51 = 51
    line52 = 52
    return line52


# Performance and Style Issues

def inefficient_loop():
    """PERF001: Using range(len()) instead of enumerate"""
    items = ['a', 'b', 'c', 'd', 'e']
    for i in range(len(items)):  # Use enumerate instead!
        print(f"{i}: {items[i]}")


def unnecessary_comparison(flag):
    """STYLE001: Comparing with True/False"""
    if flag is True:  # Just use 'if flag:'
        return True
    if flag is False:  # Just use 'if not flag:'
        return False


# Import Issues

from os import *  # IMP001: Wildcard import!


# Class Issues

class TooManyInstanceVars:
    """COMP005: Too many instance variables"""
    
    def __init__(self):
        self.var1 = 1
        self.var2 = 2
        self.var3 = 3
        self.var4 = 4
        self.var5 = 5
        self.var6 = 6
        self.var7 = 7
        self.var8 = 8
        self.var9 = 9
        self.var10 = 10
        self.var11 = 11
        self.var12 = 12


# Assert Issues

def validate_input(value):
    """REL001/REL002: Using assert for validation"""
    assert value > 0  # Don't use assert for validation!
    return value * 2


# Helper functions referenced above
def risky_operation():
    pass


def something():
    pass
