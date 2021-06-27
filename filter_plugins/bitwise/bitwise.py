#!/bin/env python
import argparse


def bitwise_and(a, b):
    return int(a) & int(b)


def bitwise_or(a, b):
    return int(a) | int(b)


class FilterModule(object):
    def filters(self):
        return {
            'bitwise_and': bitwise_and,
            'bitwise_or': bitwise_or,
        }


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument(dest='op')
    parser.add_argument(dest='a')
    parser.add_argument(dest='b')
    args = parser.parse_args(argv)
    c = None
    if args.op == 'and':
        c = bitwise_and(args.a, args.b)
    elif args.op == 'or':
        c = bitwise_or(args.a, args.b)
    print(c)


if __name__ == '__main__':
    main()
