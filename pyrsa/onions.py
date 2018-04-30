import time
from multiprocessing import Process, Queue, Event, cpu_count
from hashlib import sha1
from base64 import b32encode
from pyrsa.keyinfo import KeyInfo
from pyrsa.primes import find_prime, check_pair
from pyrsa.parse import encode_private_key, encode_public_key
from typing import NamedTuple, Optional
from gmpy2 import gcd, invert

TOR_KEY_BITS = 1024
EMIN = 0x10001
EMAX = 0xFFFFFFFFFF


def make_onion(modulus: int, public_exponent: int) -> bytes:
    return b32encode(
        sha1(
            encode_public_key(
                KeyInfo(modulus, public_exponent)
            )
        ).digest()
    )[:16].lower()


def prime_info(bits):
    primes = []
    while True:
        q = find_prime(bits)
        for p in primes:
            modulus, totient = check_pair(p, q)
            if modulus:
                yield p, q, modulus, totient
        primes.append(q)


class WorkResult(NamedTuple):
    trials: int
    domain: Optional[bytes] = None
    key: Optional[KeyInfo] = None


class Worker(Process):
    def __init__(self, pattern: bytes, results: Queue, stop: Event):
        super().__init__()
        self.pattern = pattern
        self.results = results
        self.stop = stop

    def run(self):
        pattern = self.pattern
        plen = len(pattern)
        stop_is_set = self.stop.is_set
        trials = 0
        try:
            for info in prime_info(TOR_KEY_BITS):
                p, q, modulus, totient = info
                for public_exponent in range(EMIN, EMAX):
                    if stop_is_set():
                        self.results.put(WorkResult(trials))
                        return
                    trials += 1
                    domain = make_onion(modulus, public_exponent)
                    if (domain[:plen] == pattern) and gcd(totient, public_exponent) == 1:
                        key = KeyInfo(modulus,
                                      public_exponent,
                                      invert(public_exponent, totient),
                                      p,
                                      q)
                        result = WorkResult(trials, domain, key)
                        self.results.put(result)
                        self.stop.set()
                        return
        except KeyboardInterrupt:
            self.results.put(WorkResult(trials))


def find_domain(pattern: bytes):
    start = time.time()
    procs = []
    results = Queue()
    stop = Event()
    n = cpu_count()
    for i in range(n):
        worker = Worker(pattern, results, stop)
        worker.start()
        procs.append(worker)


    total_trials = 0
    domain = None
    key = None
    for i in range(n):
        result: WorkResult = results.get()
        total_trials += result.trials
        if result.domain:
            domain = result.domain.decode()
            key = result.key

    for proc in procs:
        proc.join()

    end = time.time()
    duration = int(end - start + 0.5)
    message = 'Found {}.onion in {} seconds, {} trials.'
    print('+{:-^62}+'.format(''))
    print('|{:^62}|'.format(message.format(domain, duration, total_trials)))
    print('+{:-^62}+'.format(''))
    print(encode_private_key(key).decode())


if __name__ == '__main__':
    import sys
    find_domain(sys.argv[1].encode())
