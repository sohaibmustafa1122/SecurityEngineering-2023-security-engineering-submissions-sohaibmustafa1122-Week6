# SecurityEngineering-2023-security-engineering-submissions-sohaibmustafa1122-Week6
Week 6



# Task 1: Secure Running Environment

When it comes to secure computing environments, understanding the security capabilities and limitations of different technologies is crucial for making informed decisions. Two widely used concepts in this regard are Trusted Platform Module (TPM) and Containers.

Trusted Platform Module (TPM):

TPM is a hardware-based security feature that provides a dedicated microcontroller for cryptographic operations, such as secure storage of encryption keys, certificates, and passwords. It is integrated into modern devices and serves as a foundation for ensuring device integrity. TPM enables secure boot processes, which verify that the operating system has not been tampered with, and supports disk encryption methods like BitLocker, ensuring that data remains protected even if the device is stolen (Schneier, 2015). However, TPM has its limitations. Being hardware-dependent, its security is constrained by the physical environment it operates in. If attackers gain physical access, they could attempt hardware tampering. Additionally, TPM cannot protect against software-level vulnerabilities or advanced malware that compromises the operating system directly.

Containers:

Containers are lightweight virtualization tools that package applications and their dependencies into isolated environments, ensuring consistent execution across different platforms. Technologies like Docker have made containers popular for their efficiency and portability. Containers excel in isolating applications and preventing them from interfering with each other, which strengthens security in multi-tenant environments (Merkel, 2014). However, their reliance on shared host operating systems introduces vulnerabilities. If a container escape exploit occurs, attackers can gain access to the host system and potentially other containers. Unlike virtual machines, containers lack hardware-level isolation, making them more susceptible to kernel exploits. Therefore, securing the host operating system and using complementary tools, such as container runtime security, is essential to mitigate risks.

Comparison:

Both TPM and Containers offer unique strengths and weaknesses in secure computing environments. TPM provides robust hardware-level protection but is limited to physical threats and software attacks. Containers offer efficient isolation but require rigorous host security to address shared system vulnerabilities.

References

Merkel, D. (2014). Docker: Lightweight Linux containers for consistent development and deployment. Linux Journal, 2014(239), 2.

Schneier, B. (2015). Data and Goliath: The Hidden Battles to Collect Your Data and Control Your World. W. W. Norton & Company.


# Task 2: Supply Chain Attacks
Securing the Supply Chain: Mitigating Risks for Networking Hardware and Software Companies

Supply chain security is crucial for companies involved in manufacturing and selling networking hardware and software, especially when third-party actors are part of the process. The integration of multiple actors such as part suppliers, transportation companies, in-house and outsourced employees, and storage facilities exposes the supply chain to risks like tampering, intellectual property theft, and malware injection. Below is an analysis of actions and strategies to secure the supply chain while addressing potential challenges.

Key Actions to Secure the Supply Chain

Supplier Assessment and Certification

Implementation: Establish a rigorous assessment process for part suppliers. Suppliers should be required to adhere to security standards such as ISO/IEC 27001 for information security and NIST Cybersecurity Framework.

Reasoning: This ensures that suppliers maintain robust cybersecurity practices and reduce risks like counterfeit parts or malicious hardware being introduced.

Potential Challenges: Increased auditing might strain relationships with smaller suppliers who lack resources for certification. The company may need to provide training or assistance.

Firmware and Software Verification

Implementation: Use cryptographic signing for firmware and software updates. Every update must be signed by the manufacturer and verified by devices before installation.

Reasoning: This prevents unauthorized modifications to the firmware and protects against malicious updates, similar to those observed in the SolarWinds attack.

Potential Challenges: This approach requires a secure key management system, and any compromise of private keys could undermine the entire system.

Incorporating TPM (Trusted Platform Module)

Implementation: Embed TPM in all routers and networking devices. TPM secures hardware by integrating cryptographic keys into devices, ensuring data integrity and authenticity.

Reasoning: TPM protects against physical tampering and ensures secure boot processes, thus safeguarding hardware integrity.

Potential Challenges: Manufacturing costs may increase, and training will be required for employees to manage TPM technology effectively.

Monitoring Transportation Security

Implementation: Implement GPS tracking and tamper-evident packaging for transporting sensitive components or devices.

Reasoning: Ensures that hardware is not tampered with during transit, reducing risks of physical or software compromise.

Potential Challenges: GPS tracking requires investments in IoT technology, and tamper-evident packaging must be rigorously tested to ensure reliability.

User Behavior Analytics (UBA)

Implementation: Deploy UBA tools to monitor employee behavior for unusual access patterns or data usage.

Reasoning: Insider threats are a significant risk. UBA detects anomalous behavior that might indicate malicious intent or compromised accounts.

Potential Challenges: Privacy concerns among employees could arise, requiring clear communication about the intent and scope of monitoring.

Third-Party Code and Tool Auditing

Implementation: Regularly audit third-party libraries, tools, and code used in manufacturing and software development.

Reasoning: Detect and mitigate risks of vulnerabilities embedded in third-party components before they can be exploited.

Potential Challenges: Regular audits demand dedicated resources and skilled personnel to conduct in-depth reviews.
Addressing Potential Problems
While these measures improve supply chain security, they also bring challenges:

Increased Costs: Rigorous measures such as TPM and cryptographic signing require investment in technology and training.

Vendor Pushback: Smaller suppliers may struggle to meet stringent security requirements, potentially disrupting supply continuity.

Integration Complexity: Introducing tools like UBA and secure transportation requires system integration, which can be time-consuming and error-prone.

Despite these challenges, securing the supply chain is essential to safeguard the company's reputation and products. Adopting these measures not only reduces risks but also enhances trust with customers and stakeholders.



Visual work: (in the repos)

Supply Chain Actors and Their Associated Risks:

A bar chart highlighting the risk levels of employees, suppliers, transportation companies, and storage facilities.
Effectiveness of Risk Mitigation Measures:

A pie chart showing the effectiveness of measures such as supplier assessment, cryptographic signing, TPM, and UBA.
Supply Chain Process Flow:

A line chart illustrating the stages and time distribution in the supply chain, from suppliers to storage.
Cybersecurity Investment Priorities:

A horizontal bar chart showcasing the percentage distribution of investment priorities, emphasizing supply chain security, employee training, incident response, and system upgrades.




# Task 3: Securing Docker:
Despite multiple attempts, I was unable to complete the task of auditing and securing the Dockerfile. While I successfully identified warnings using Hadolint, such as pinning the base image and package versions, I encountered issues during implementation. The Docker build process failed with an internal error, and missteps like running RUN commands in PowerShell instead of the Dockerfile added to the challenges. Despite my efforts to resolve these problems, I couldn't proceed beyond these errors.


# Task 3A: 
I attempted to complete the task of building and running a secure Docker image using a simple Dockerfile and the docker build command. Despite following the proper steps, including creating a valid Dockerfile with a base image (FROM alpine:latest or a pinned version like alpine:3.18), I encountered persistent errors during the build process. Specifically, the docker build -t secure-alpine . command failed with an "Internal: stream terminated by RST_STREAM with error code: INTERNAL_ERROR" message, indicating a potential issue with the Docker daemon or network connectivity. Additionally, even after ensuring the Dockerfile syntax was correct and retrying the process, the built image could not be found locally, leading to a failure when trying to run the container. Despite multiple attempts to troubleshoot, including pruning unused Docker resources and verifying the Dockerfile content, I was unable to resolve the issue, likely due to underlying system-level or network-related constraints.


# Task 3b: 
I attempted to complete Task 3B by working through the instructions for container image analysis using Trivy. Initially, I pulled the Trivy image successfully using the docker pull aquasec/trivy command. I then tried to analyze my container image. While attempting to run Trivy on my Dockerfile, I encountered an issue with the stream terminating due to an INTERNAL_ERROR. Despite repeated efforts to execute the command and resolve the error, I was unable to proceed further or retrieve vulnerability scan results. This is where my progress ended, leaving the task incomplete.


# Task 3C: 

I attempted to work on Task 3C by pulling and running the falcosecurity/falco-no-driver:latest container for runtime security monitoring. While following the setup instructions, I encountered errors related to mounting directories with the -v flag and running the Falco image, as the system did not recognize the image name or commands. Additionally, I tried triggering alerts using a privileged container with Alpine Linux, but I couldn't proceed further due to these technical challenges.


