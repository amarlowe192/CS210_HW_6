#include <cstdint>
#include <iomanip>
#include <iostream>
#include <optional>
#include <string>
#include <utility>
#include <vector>


uint64_t demoHash(const std::string& s) {
    uint64_t h = 1469598103934665603ULL;
    for (unsigned char c : s) {
        h = (h ^ c) * 1099511628211ULL;
    }
    return h;
}

struct UserRecord {
    std::string username;
    std::string displayName;
    std::string salt;
    uint64_t passwordHash{};
};

enum class CollisionStrategy { SeparateChaining, LinearProbing, QuadraticProbing, DoubleHashing };

class HashTable {
public:
    explicit HashTable(CollisionStrategy strategy, std::size_t initialCapacity = 5)
        : strategy_(strategy), capacity_(nextPrime(initialCapacity)) {
        resetStorage(capacity_);
    }

    bool insert(const UserRecord& user) {
        if (find(user.username) != nullptr) {
            return updateExisting(user);
        }
        if (static_cast<double>(size_ + 1) / capacity_ > maxLoad()) {
            rehash(nextPrime(capacity_ * 2 + 1));
        }
        return insertRaw(user);
    }

    const UserRecord* find(const std::string& username) const {
        std::size_t start = primaryIndex(username);
        if (strategy_ == CollisionStrategy::SeparateChaining) {
            for (const UserRecord& user : chains_[start]) {
                if (user.username == username) return &user;
            }
            return nullptr;
        }
        for (std::size_t i = 0; i < capacity_; ++i) {
            const Slot& slot = slots_[probeIndex(username, start, i)];
            if (slot.state == SlotState::Empty) return nullptr;
            if (slot.state == SlotState::Occupied && slot.user.username == username) return &slot.user;
        }
        return nullptr;
    }

    bool remove(const std::string& username) {
        std::size_t start = primaryIndex(username);
        if (strategy_ == CollisionStrategy::SeparateChaining) {
            std::vector<UserRecord>& bucket = chains_[start];
            for (std::size_t i = 0; i < bucket.size(); ++i) {
                if (bucket[i].username == username) {
                    bucket.erase(bucket.begin() + static_cast<long>(i));
                    --size_;
                    return true;
                }
            }
            return false;
        }
        for (std::size_t i = 0; i < capacity_; ++i) {
            Slot& slot = slots_[probeIndex(username, start, i)];
            if (slot.state == SlotState::Empty) return false;
            if (slot.state == SlotState::Occupied && slot.user.username == username) {
                slot.state = SlotState::Deleted;
                --size_;
                ++tombstones_;
                if (tombstones_ > capacity_ / 4) rehash(capacity_);
                return true;
            }
        }
        return false;
    }

    double loadFactor() const { return static_cast<double>(size_) / capacity_; }
    std::size_t size() const { return size_; }
    std::size_t capacity() const { return capacity_; }

    std::string strategyName() const {
        switch (strategy_) {
            case CollisionStrategy::SeparateChaining: return "separate chaining";
            case CollisionStrategy::LinearProbing: return "linear probing";
            case CollisionStrategy::QuadraticProbing: return "quadratic probing";
            case CollisionStrategy::DoubleHashing: return "double hashing";
        }
        return "unknown";
    }

private:
    enum class SlotState { Empty, Occupied, Deleted };
    struct Slot { SlotState state = SlotState::Empty; UserRecord user{}; };

    CollisionStrategy strategy_;
    std::size_t capacity_;
    std::size_t size_ = 0;
    std::size_t tombstones_ = 0;
    std::vector<std::vector<UserRecord>> chains_;
    std::vector<Slot> slots_;

    static bool isPrime(std::size_t n) {
        if (n < 2) return false;
        for (std::size_t d = 2; d * d <= n; ++d) if (n % d == 0) return false;
        return true;
    }
    static std::size_t nextPrime(std::size_t n) {
        while (!isPrime(n)) ++n;
        return n;
    }
    double maxLoad() const {
        return strategy_ == CollisionStrategy::SeparateChaining ? 0.75 : 0.55;
    }
    void resetStorage(std::size_t newCapacity) {
        capacity_ = newCapacity;
        chains_.clear();
        slots_.clear();
        if (strategy_ == CollisionStrategy::SeparateChaining) chains_.resize(capacity_);
        else slots_.resize(capacity_);
    }
    std::size_t primaryIndex(const std::string& key) const { return demoHash(key) % capacity_; }
    std::size_t probeIndex(const std::string& key, std::size_t start, std::size_t i) const {
        if (strategy_ == CollisionStrategy::LinearProbing) return (start + i) % capacity_;
        if (strategy_ == CollisionStrategy::QuadraticProbing) return (start + i * i) % capacity_;
        std::size_t step = 1 + (demoHash(key + "#step") % (capacity_ - 1));
        return (start + i * step) % capacity_;
    }
    bool updateExisting(const UserRecord& user) {
        std::size_t start = primaryIndex(user.username);
        if (strategy_ == CollisionStrategy::SeparateChaining) {
            for (UserRecord& current : chains_[start]) {
                if (current.username == user.username) { current = user; return true; }
            }
        } else {
            for (std::size_t i = 0; i < capacity_; ++i) {
                Slot& slot = slots_[probeIndex(user.username, start, i)];
                if (slot.state == SlotState::Empty) break;
                if (slot.state == SlotState::Occupied && slot.user.username == user.username) {
                    slot.user = user;
                    return true;
                }
            }
        }
        return false;
    }
    bool insertRaw(const UserRecord& user) {
        std::size_t start = primaryIndex(user.username);
        if (strategy_ == CollisionStrategy::SeparateChaining) {
            chains_[start].push_back(user);
            ++size_;
            return true;
        }
        std::optional<std::size_t> firstDeleted;
        for (std::size_t i = 0; i < capacity_; ++i) {
            std::size_t index = probeIndex(user.username, start, i);
            Slot& slot = slots_[index];
            if (slot.state == SlotState::Deleted && !firstDeleted) firstDeleted = index;
            if (slot.state == SlotState::Empty) {
                std::size_t destination = firstDeleted.value_or(index);
                if (slots_[destination].state == SlotState::Deleted) --tombstones_;
                slots_[destination].state = SlotState::Occupied;
                slots_[destination].user = user;
                ++size_;
                return true;
            }
        }
        if (firstDeleted) {
            Slot& slot = slots_[*firstDeleted];
            slot.state = SlotState::Occupied;
            slot.user = user;
            --tombstones_;
            ++size_;
            return true;
        }
        return false;
    }
    std::vector<UserRecord> allUsers() const {
        std::vector<UserRecord> result;
        if (strategy_ == CollisionStrategy::SeparateChaining) {
            for (const auto& bucket : chains_) for (const UserRecord& user : bucket) result.push_back(user);
        } else {
            for (const Slot& slot : slots_) if (slot.state == SlotState::Occupied) result.push_back(slot.user);
        }
        return result;
    }
    void rehash(std::size_t newCapacity) {
        std::vector<UserRecord> oldUsers = allUsers();
        size_ = 0;
        tombstones_ = 0;
        resetStorage(nextPrime(newCapacity));
        for (const UserRecord& user : oldUsers) insertRaw(user);
    }
};

const std::string PEPPER = "CS210 classroom pepper - not secret";

UserRecord makeUser(const std::string& username, const std::string& name,
                    const std::string& salt, const std::string& password) {
    return {username, name, salt, demoHash(salt + password + PEPPER)};
}

bool verifyPassword(const UserRecord& user, const std::string& submittedPassword) {
    return demoHash(user.salt + submittedPassword + PEPPER) == user.passwordHash;
}

namespace Ui {
    const char* reset = "\033[0m";
    const char* lightBlue = "\033[96m";
    const char* purple = "\033[95m";
    const char* gold = "\033[93m";
    void divider() { std::cout << purple << "================================================" << reset << "\n"; }
    void login(const HashTable& users, const std::string& username, const std::string& password) {
        divider();
        std::cout << lightBlue << "                AUTH" << reset << "\n";
        std::cout << "  Username: " << username << "\n";
        const UserRecord* user = users.find(username);
        if (!user) std::cout << gold << "  Result: Account not found" << reset << "\n";
        else if (verifyPassword(*user, password))
            std::cout << lightBlue << "  Result: Welcome back, " << user->displayName << "!" << reset << "\n";
        else std::cout << gold << "  Result: Password did not match" << reset << "\n";
        divider();
    }
}

std::pair<std::string, std::string> collisionPair(std::size_t capacity) {
    std::vector<std::pair<std::size_t, std::string>> seen;
    for (int i = 0; ; ++i) {
        std::string candidate = "collision_user_" + std::to_string(i);
        std::size_t bucket = demoHash(candidate) % capacity;
        for (const auto& item : seen) if (item.first == bucket) return {item.second, candidate};
        seen.push_back({bucket, candidate});
    }
}

int main() {
    std::cout << "HashTable authentication demo (C++17)\n\n";

    auto pair = collisionPair(5);
    std::cout << "Collision exercise: '" << pair.first << "' and '" << pair.second
              << "' both start in bucket " << (demoHash(pair.first) % 5) << " of 5.\n";
    for (CollisionStrategy strategy : {CollisionStrategy::SeparateChaining, CollisionStrategy::LinearProbing,
                                       CollisionStrategy::QuadraticProbing, CollisionStrategy::DoubleHashing}) {
        HashTable trial(strategy, 5);
        trial.insert(makeUser(pair.first, "First", "s1", "pw1"));
        trial.insert(makeUser(pair.second, "Second", "s2", "pw2"));
        std::cout << "  " << std::left << std::setw(18) << trial.strategyName()
                  << ": both collision keys found = "
                  << ((trial.find(pair.first) && trial.find(pair.second)) ? "yes" : "no") << "\n";
    }

    HashTable users(CollisionStrategy::SeparateChaining, 5);
    std::cout << "\nChosen strategy: " << users.strategyName() << "\n";
    std::cout << "Initial capacity: " << users.capacity() << "\n";
    std::vector<UserRecord> seed = {
        makeUser("allie", "Allie", "sA7!", "moonlight"),
        makeUser("mika", "Mika", "sB2?", "violet"),
        makeUser("jordan", "Jordan", "sC9#", "orbit"),
        makeUser("samira", "Samira", "sD4$", "seashell"),
        makeUser("kai", "Kai", "sE1%", "starlight")
    };
    for (const UserRecord& user : seed) {
        std::size_t before = users.capacity();
        users.insert(user);
        std::cout << "Inserted " << std::setw(7) << user.username << " | load factor = "
                  << std::fixed << std::setprecision(2) << users.loadFactor();
        if (users.capacity() != before) std::cout << " | REHASH: " << before << " -> " << users.capacity();
        std::cout << "\n";
    }
    std::cout << "\n";
    Ui::login(users, "allie", "moonlight");       // successful login
    Ui::login(users, "allie", "wrong-password");  // failed password
    Ui::login(users, "nobody", "anything");       // unknown user

    std::cout << "\nRemove 'mika': " << (users.remove("mika") ? "removed" : "not found") << "\n";
    std::cout << "Find 'mika' after removal: " << (users.find("mika") ? "found" : "not found") << "\n";
    std::cout << "Final size: " << users.size() << ", capacity: " << users.capacity()
              << ", load factor: " << users.loadFactor() << "\n";
}
