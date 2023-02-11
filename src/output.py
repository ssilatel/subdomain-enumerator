from abc import ABC, abstractmethod

class Output(ABC):
    def __init__(self, subject):
        subject.attach(self)
        self.subject = subject

    @abstractmethod
    def update(self, domains) -> None:
        pass

    @abstractmethod
    def end_output(self) -> None:
        pass    


class ScreenOutput(Output):
    def __init__(self, subject):
        super().__init__(subject)
        self.found_domains = []

    def update(self, domains) -> None:
        for domain in domains:
            if domain not in self.found_domains:
                self.found_domains.append(domain)
                print(f"{domain}")

    def end_output(self) -> None:
        pass


class FileOutput(Output):
    def __init__(self, subject):
        super().__init__(subject)
        self.output_filepath = subject.output_file
        self.output_file = open(subject.output_file, mode="w", encoding="utf-8")
        self.found_domains = []

    def update(self, domains) -> None:
        for domain in domains:
            if domain not in self.found_domains:
                self.found_domains.append(domain)
                self.output_file.write(f"{domain}\n")

    def end_output(self) -> None:
        self.output_file.close()
