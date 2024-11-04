from algorithms.dsa import dsa_metrics
from algorithms.rsa import rsa_metrics
from algorithms.ecDSA import ecdsa_metrics

input = input("Enter a string: ")

dsa_metrics(input)
rsa_metrics(input)
ecdsa_metrics(input)
