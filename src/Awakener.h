
#ifndef SRC_AWAKENER_H
#define SRC_AWAKENER_H

#include <string>
#include <map>
#include <vector>

class Awakener {
public:
    Awakener(std::string  interface_name );
    ~Awakener();
    void wake(const std::string& name);
    void add(const std::string& name, const std::string& mac);
private:
    std::map<std::string, std::string> hosts_;
    std::string interface_name_;
    int open_socket_;
    int start_socket();
    void send_wol(const std::string& mac);
    std::vector<std::string> split(const std::string& s, char delimiter);
};


#endif //SRC_AWAKENER_H
