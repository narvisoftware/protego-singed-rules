#!/bin/bash

rm CreateSignature.class

javac CreateSignature.java
java CreateSignature "$@"